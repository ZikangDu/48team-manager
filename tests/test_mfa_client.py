"""Offline contract of the ChatGPT MFA protocol client (app/integrations/openai/mfa.py).

Pure unit tests: a scripted transport answers every request, so nothing here opens a
connection, a browser or a database. Every key, token and identifier is synthetic.
"""
import asyncio
import base64
import contextlib
import io
import json
import logging
import traceback
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.core.jwt import jwt_parser
from app.integrations.openai.mfa import (
    ChatGPTMfaClient, MfaError, MfaTransportError, generate_totp, normalize_totp_secret, totp_seconds_left)

EMAIL = 'member@example.com'
OTHER_EMAIL = 'intruder@example.com'
PROFILE_CLAIM = 'https://api.openai.com/profile'
RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'  # RFC 6238 appendix B key: ASCII "12345678901234567890"
OLD_SECRET = 'JBSWY3DPEHPK3PXP'
NEW_SECRET = 'KRSXG5DSNFXGOIDBKRSXG5DSNFXGOIDB'
PADDED_SECRET = base64.b32encode(b'synthetic-16byte').decode()  # 26 characters followed by '======'
OLD_FACTOR = 'factor-old-fixture'
NEW_FACTOR = 'factor-new-fixture'
ENROLL_SESSION = 'enrolment-session-fixture'
CODE = '492039'  # any six digits: the client forwards a code, it never computes one
BODY_MARKER = 'REMOTE-BODY-TEXT-MUST-NOT-LEAK'

SESSION_PATH = '/api/auth/session'
INFO_PATH = '/backend-api/accounts/mfa_info'
DISABLE_PATH = '/backend-api/accounts/mfa/user/disable_in_house'
ENROLL_PATH = '/backend-api/accounts/mfa/enroll'
ACTIVATE_PATH = '/backend-api/accounts/mfa/user/activate_enrollment'
OPERATIONS = ('session', 'info', 'disable', 'enroll', 'activate')
SOURCES = ('session user', 'jwt email claim', 'jwt profile claim')
FIXED_CODE = r'\A[a-z][a-z0-9_]{2,59}\Z'
REMOTE_CODE = r'\A[A-Za-z0-9_]{0,80}\Z'


class _Absent:
    def __repr__(self):
        return 'ABSENT'


ABSENT = _Absent()  # marks a JSON member that is left out of an answer altogether


def _segment(value) -> str:
    raw = value if isinstance(value, bytes) else json.dumps(value, separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def access_token(claim_email=EMAIL, profile_email=EMAIL, **claims) -> str:
    """Synthetic JWT; app.core.jwt reads the claims without verifying the signature."""
    payload = {'sub': 'user-fixture', 'exp': 4102444800, **claims}
    if claim_email is not None:
        payload['email'] = claim_email
    if profile_email is not None:
        payload[PROFILE_CLAIM] = {'email': profile_email, 'email_verified': True}
    return '.'.join((_segment({'alg': 'HS256', 'typ': 'JWT'}), _segment(payload), _segment(b'synthetic-signature')))


TOKEN = access_token()
ANONYMOUS_TOKEN = access_token(claim_email=None, profile_email=None)


def session_body(user_email=EMAIL, token=TOKEN, **extra) -> str:
    user = {'id': 'user-fixture', 'name': 'Fixture Member'}
    if user_email is not None:
        user['email'] = user_email
    return json.dumps({'user': user, 'expires': '2099-01-01T00:00:00.000Z', 'accessToken': token, **extra})


def identity_body(emails) -> tuple[str, str]:
    """Session answer whose three email sources are (session user, JWT email, JWT profile email)."""
    user_email, claim_email, profile_email = emails
    token = access_token(claim_email=claim_email, profile_email=profile_email)
    return session_body(user_email=user_email, token=token), token


def enroll_body(secret=NEW_SECRET, session_id=ENROLL_SESSION, factor_id=NEW_FACTOR, **extra) -> str:
    return json.dumps({'secret': secret, 'session_id': session_id,
                       'factor': {'id': factor_id, 'factor_type': 'totp'}, **extra})


# One acknowledged answer per call; used to prove that a variation alone flips the outcome.
ACCEPTED = {
    'session': {'user': {'id': 'user-fixture', 'email': EMAIL}, 'accessToken': TOKEN},
    'info': {'mfa_enabled': True, 'factors': {'totp': [{'id': OLD_FACTOR}]}},
    'disable': {},
    'enroll': {'secret': NEW_SECRET, 'session_id': ENROLL_SESSION, 'factor': {'id': NEW_FACTOR}},
    'activate': {'success': True},
}
HOSTILE_BODY = json.dumps({
    'error': {'code': 'remote_failure', 'param': ENROLL_SESSION,
              'message': f'{BODY_MARKER} {TOKEN} {NEW_SECRET} {CODE}'},
    'detail': {'code': 'remote_detail', 'msg': BODY_MARKER}, 'message': BODY_MARKER,
    'secret': NEW_SECRET, 'session_id': ENROLL_SESSION, 'accessToken': TOKEN, 'access_token': TOKEN,
    'user': {'email': EMAIL}, 'mfa_enabled': True, 'factors': {'totp': [{'id': NEW_FACTOR}]}})
HOSTILE_PAGE = f'<html><body>{BODY_MARKER} {TOKEN} {NEW_SECRET} {CODE} {ENROLL_SESSION}</body></html>'
FORBIDDEN = (BODY_MARKER, TOKEN, TOKEN.split('.')[1], NEW_SECRET, ENROLL_SESSION, CODE)


class ScriptedTransport:
    """Answers each request with the next scripted step: a (status, text) pair or an exception to raise."""

    def __init__(self, *steps):
        self.steps = list(steps)
        self.requests = []      # what was sent, copied at the moment of the request
        self.live_headers = []  # the very dict objects the client handed over

    async def request(self, method, path, *, headers, body):
        self.live_headers.append(headers)
        self.requests.append({'method': method, 'path': path, 'body': body,
                              'headers': {str(name).lower(): value for name, value in headers.items()}})
        if not self.steps:
            raise AssertionError(f'unscripted request: {method} {path}')
        step = self.steps.pop(0)
        if isinstance(step, BaseException):
            raise step
        return step


async def opened_client(*steps):
    """A client whose session check already passed, followed by the scripted answers."""
    transport = ScriptedTransport((200, session_body()), *steps)
    client = ChatGPTMfaClient(transport, expected_email=EMAIL)
    await client.open_session()
    return client, transport


def bearer_calls(client) -> dict:
    return {'info': client.state, 'disable': lambda: client.disable(OLD_FACTOR), 'enroll': client.enroll,
            'activate': lambda: client.activate(code=CODE, session_id=ENROLL_SESSION)}


async def call_once(operation, step):
    """One client call against one scripted answer -> (MfaError or None, result, client, transport)."""
    if operation == 'session':
        transport = ScriptedTransport(step)
        client = ChatGPTMfaClient(transport, expected_email=EMAIL)
        invoke = client.open_session
    else:
        client, transport = await opened_client(step)
        invoke = bearer_calls(client)[operation]
    try:
        return None, await invoke(), client, transport
    except MfaError as exc:
        return exc, None, client, transport


def error_surface(exc) -> str:
    """Everything a log line, an error report or a result built from the exception could show."""
    parts, seen = [], set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        parts += [str(exc), repr(exc), repr(exc.args), repr(vars(exc)),
                  *traceback.format_exception_only(type(exc), exc)]
        exc = exc.__cause__ or (None if exc.__suppress_context__ else exc.__context__)
    return '\n'.join(parts)


class ClientCase(unittest.IsolatedAsyncioTestCase):
    def assert_no_leak(self, exc, *forbidden):
        surface = error_surface(exc)
        for value in forbidden:
            self.assertNotIn(value, surface)

    async def assert_session_missing(self, client, transport):
        """Every bearer call is refused locally: nothing is sent."""
        sent = len(transport.requests)
        for name, call in bearer_calls(client).items():
            with self.assertRaises(MfaError, msg=name) as caught:
                await call()
            self.assertEqual((caught.exception.code, caught.exception.outcome), ('session_missing', 'rejected'), name)
            self.assertTrue(caught.exception.rejected)
        self.assertEqual(len(transport.requests), sent)

    async def failure(self, operation, step, outcome):
        """The call must fail with this outcome after exactly one request; returns the MfaError."""
        error, _, client, transport = await call_once(operation, step)
        self.assertIsNotNone(error, 'the answer was accepted as a success')
        self.assertEqual(error.outcome, outcome, error.code)
        self.assertEqual(error.rejected, outcome == 'rejected')
        # Sent once and never repeated by the client: retries belong to the durable state machine.
        self.assertEqual(len(transport.requests), 1 if operation == 'session' else 2)
        self.assertEqual(transport.steps, [])
        self.assertEqual(transport.live_headers[-1], {})
        self.assertIsInstance(error.status, int)
        self.assertNotIsInstance(error.status, bool)
        self.assertRegex(error.code, FIXED_CODE)
        self.assertIsInstance(error.remote_code, str)
        self.assertRegex(error.remote_code, REMOTE_CODE)
        self.assert_no_leak(error, TOKEN, TOKEN.split('.')[1])
        if operation == 'session':
            await self.assert_session_missing(client, transport)  # a failed session read leaves no token behind
        return error

    async def success(self, operation, step):
        """The call must be acknowledged after exactly one request; returns its result."""
        error, result, _, transport = await call_once(operation, step)
        self.assertIsNone(error, error and f'refused as {error.code} ({error.outcome})')
        self.assertEqual(len(transport.requests), 1 if operation == 'session' else 2)
        self.assertEqual(transport.live_headers[-1], {})
        return result


class TotpCodeTests(unittest.TestCase):
    def test_rfc6238_sha1_vectors_as_six_digits(self):
        vectors = {59: '287082', 1111111109: '081804', 1111111111: '050471', 1234567890: '005924',
                   2000000000: '279037', 20000000000: '353130'}
        for stamp, code in vectors.items():
            with self.subTest(timestamp=stamp):
                self.assertEqual(generate_totp(RFC_SECRET, timestamp=stamp), code)
                self.assertEqual(generate_totp(RFC_SECRET, timestamp=float(stamp)), code)
                self.assertRegex(generate_totp(RFC_SECRET, timestamp=stamp), r'\A[0-9]{6}\Z')

    def test_code_changes_exactly_on_30_second_boundaries(self):
        # RFC 4226 appendix D: HOTP values of the same key for counters 0..3.
        windows = {0: '755224', 30: '287082', 60: '359152', 90: '969429'}
        for start, code in windows.items():
            for offset in (0, 0.001, 15, 29, 29.999):
                with self.subTest(timestamp=start + offset):
                    self.assertEqual(generate_totp(RFC_SECRET, timestamp=start + offset), code)

    def test_default_time_is_the_current_clock(self):
        with patch('time.time', return_value=59.0):
            self.assertEqual(generate_totp(RFC_SECRET), '287082')
            self.assertEqual(generate_totp(RFC_SECRET, timestamp=None), '287082')
        with patch('time.time', return_value=1111111109.0):
            self.assertEqual(generate_totp(RFC_SECRET), '081804')

    def test_key_formatting_does_not_change_the_code(self):
        variants = ('gezdgnbvgy3tqojqgezdgnbvgy3tqojq', 'GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ',
                    'gezd-gnbv-gy3t-qojq-gezd-gnbv-gy3t-qojq', '\tGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\r\n')
        for variant in variants:
            with self.subTest(variant=variant):
                self.assertEqual(generate_totp(variant, timestamp=59), '287082')
        self.assertTrue(PADDED_SECRET.endswith('======'))
        self.assertEqual(generate_totp(PADDED_SECRET, timestamp=59),
                         generate_totp(PADDED_SECRET.rstrip('='), timestamp=59))

    def test_bad_keys_are_rejected_without_echoing_them(self):
        bad = ('', '123456', 'SECRET!', 'JBSWY3DP', 'JBSWY3DPEHPK3PX', 'JBSWY3DPEHPK3PX0', 'JBSWY3DPEHPK3PX1',
               'JBSWY3DPEHPK3PX8', 'JBSWY3DPEHPK3PX9', 'not a base32 key at all!!', None, 123456,
               b'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'])
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as caught:
                    generate_totp(value, timestamp=59)
                if isinstance(value, str) and value:
                    self.assertNotIn(value, error_surface(caught.exception))

    def test_bad_times_are_rejected(self):
        for stamp in (-1, -0.5, float('nan'), float('inf'), float('-inf'), '59', b'59', [59], {}):
            with self.subTest(timestamp=stamp):
                with self.assertRaises(ValueError) as caught:
                    generate_totp(RFC_SECRET, timestamp=stamp)
                self.assertNotIn(RFC_SECRET, error_surface(caught.exception))


class SecretNormalisationTests(unittest.TestCase):
    def test_canonical_form_drops_spaces_hyphens_case_and_padding(self):
        cases = {
            OLD_SECRET: OLD_SECRET,
            NEW_SECRET: NEW_SECRET,
            'jbswy3dpehpk3pxp': OLD_SECRET,
            'JBSW Y3DP EHPK 3PXP': OLD_SECRET,
            'jbsw-y3dp-ehpk-3pxp': OLD_SECRET,
            ' \tJBSWY3DPEHPK3PXP\r\n': OLD_SECRET,
            PADDED_SECRET: PADDED_SECRET.rstrip('='),
            PADDED_SECRET.lower(): PADDED_SECRET.rstrip('='),
        }
        for raw, canonical in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(normalize_totp_secret(raw), canonical)
                self.assertRegex(normalize_totp_secret(raw), r'\A[A-Z2-7]+\Z')
                # A canonical key is stable and produces the codes of the key as it was written.
                self.assertEqual(normalize_totp_secret(canonical), canonical)
                self.assertEqual(generate_totp(canonical, timestamp=59), generate_totp(raw, timestamp=59))

    def test_unusable_keys_raise_value_error_without_echoing_the_input(self):
        bad = ('', '   ', '123456', 'JBSWY3DP', 'JBSWY3DPEHPK3PX', 'JBSWY3DPEHPK3PX1', 'JBSWY3DPEHPK3PX8',
               'JBSWY3DP=EHPK3PXP', 'JBSWY3DPEHPK3PXP!', 'otpauth://totp/Fixture?secret=JBSWY3DPEHPK3PXP',
               None, 1234567890123456, b'JBSWY3DPEHPK3PXP', ['JBSWY3DPEHPK3PXP'], {'secret': OLD_SECRET})
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as caught:
                    normalize_totp_secret(value)
                surface = error_surface(caught.exception)
                self.assertNotIn(OLD_SECRET, surface)
                if isinstance(value, str) and value.strip():
                    self.assertNotIn(value.strip(), surface)


class SecondsLeftTests(unittest.TestCase):
    def test_window_boundaries(self):
        cases = {0: 30, 1: 29, 15: 15, 29: 1, 30: 30, 31: 29, 59: 1, 60: 30,
                 1111111109: 1, 1111111111: 29, 1234567890: 30, 2000000000: 10}
        for stamp, left in cases.items():
            with self.subTest(timestamp=stamp):
                self.assertEqual(totp_seconds_left(timestamp=stamp), left)
                # The current code is good until then, and that instant starts the next window.
                self.assertEqual((stamp + left) % 30, 0)
                self.assertEqual(generate_totp(RFC_SECRET, timestamp=stamp + left - 1),
                                 generate_totp(RFC_SECRET, timestamp=stamp))
        self.assertAlmostEqual(totp_seconds_left(timestamp=29.75), 0.25)
        self.assertAlmostEqual(totp_seconds_left(timestamp=30.25), 29.75)
        self.assertAlmostEqual(totp_seconds_left(timestamp=1234567919.5), 0.5)

    def test_result_is_always_inside_the_window(self):
        for stamp in (0, 0.001, 14.5, 29.999, 30, 30.001, 59.999, 1e9, 1e9 + 29.999, 1763600000.123):
            with self.subTest(timestamp=stamp):
                left = totp_seconds_left(timestamp=stamp)
                self.assertGreater(left, 0)
                self.assertLessEqual(left, 30)

    def test_default_time_is_the_current_clock(self):
        with patch('time.time', return_value=1111111109.0):
            self.assertEqual(totp_seconds_left(), 1)
        with patch('time.time', return_value=1234567890.0):
            self.assertEqual(totp_seconds_left(), 30)
            self.assertEqual(totp_seconds_left(timestamp=None), 30)


class MfaErrorTests(unittest.TestCase):
    def test_outcome_flag_and_empty_defaults(self):
        rejected = MfaError('disable_rejected', outcome='rejected', status=403, remote_code='not_allowed')
        self.assertTrue(rejected.rejected)
        self.assertEqual((rejected.code, rejected.outcome, rejected.status, rejected.remote_code),
                         ('disable_rejected', 'rejected', 403, 'not_allowed'))
        unknown = MfaError('activate_no_response', outcome='unknown')
        self.assertFalse(unknown.rejected)
        self.assertEqual((unknown.code, unknown.outcome), ('activate_no_response', 'unknown'))
        self.assertFalse(unknown.status)
        self.assertFalse(unknown.remote_code)
        self.assertIsInstance(unknown, Exception)


class RequestShapeTests(ClientCase):
    def assert_bearer(self, request, method, path):
        self.assertEqual((request['method'], request['path']), (method, path))
        headers = request['headers']
        self.assertEqual(headers.get('authorization'), 'Bearer ' + TOKEN)
        self.assertEqual(headers.get('x-openai-target-path'), path)
        self.assertEqual(headers.get('x-openai-target-route'), path)
        for name, value in headers.items():
            self.assertIsInstance(value, str, name)

    def assert_json_body(self, request, expected):
        self.assertIsInstance(request['body'], str)
        self.assertEqual(json.loads(request['body']), expected)
        self.assertIn('application/json', request['headers'].get('content-type', '').lower())

    async def run_sequence(self):
        transport = ScriptedTransport(
            (200, session_body()),
            (200, json.dumps({'mfa_enabled': True, 'native_default_factor_id': OLD_FACTOR,
                              'factors': {'totp': [{'id': OLD_FACTOR}]}})),
            (204, ''),
            (200, enroll_body()),
            (200, json.dumps({'success': True})),
            (200, json.dumps({'mfa_enabled': True, 'native_default_factor_id': NEW_FACTOR,
                              'factors': {'totp': [{'id': NEW_FACTOR}]}})))
        client = ChatGPTMfaClient(transport, expected_email=EMAIL)
        opened = await client.open_session()
        before = await client.state()
        disabled = await client.disable(before.active_factor_id)
        enrollment = await client.enroll()
        code = generate_totp(enrollment.secret, timestamp=59)
        activated = await client.activate(code=code, session_id=enrollment.session_id)
        after = await client.state()
        client.close()
        return SimpleNamespace(transport=transport, before=before, enrollment=enrollment, code=code, after=after,
                               returned=[opened, before, disabled, enrollment, activated, after])

    async def test_session_is_read_without_a_bearer(self):
        transport = ScriptedTransport((200, session_body()), (200, session_body()))
        client = ChatGPTMfaClient(transport, expected_email=EMAIL)
        await client.open_session()
        await client.open_session()  # even with a token in hand the session read stays cookie-only
        self.assertEqual(len(transport.requests), 2)
        for request in transport.requests:
            self.assertEqual((request['method'], request['path']), ('GET', SESSION_PATH))
            self.assertIsNone(request['body'])
            self.assertNotIn('authorization', request['headers'])
            self.assertNotIn(TOKEN, repr(request))

    async def test_status_read_shape(self):
        client, transport = await opened_client((200, json.dumps({'mfa_enabled': False})))
        await client.state()
        self.assertEqual(len(transport.requests), 2)
        self.assert_bearer(transport.requests[1], 'GET', INFO_PATH)
        self.assertIsNone(transport.requests[1]['body'])

    async def test_disable_shape(self):
        client, transport = await opened_client((200, '{}'))
        await client.disable(OLD_FACTOR)
        self.assertEqual(len(transport.requests), 2)
        self.assert_bearer(transport.requests[1], 'POST', DISABLE_PATH)
        self.assert_json_body(transport.requests[1], {'factor_id': OLD_FACTOR})

    async def test_enroll_shape(self):
        client, transport = await opened_client((200, enroll_body()))
        await client.enroll()
        self.assertEqual(len(transport.requests), 2)
        self.assert_bearer(transport.requests[1], 'POST', ENROLL_PATH)
        self.assert_json_body(transport.requests[1], {'factor_type': 'totp'})

    async def test_activate_shape(self):
        client, transport = await opened_client((200, json.dumps({'success': True})))
        await client.activate(code=CODE, session_id=ENROLL_SESSION)
        self.assertEqual(len(transport.requests), 2)
        self.assert_bearer(transport.requests[1], 'POST', ACTIVATE_PATH)
        self.assert_json_body(transport.requests[1],
                              {'code': CODE, 'factor_type': 'totp', 'session_id': ENROLL_SESSION})

    async def test_full_sequence_in_order_and_the_key_is_never_sent(self):
        run = await self.run_sequence()
        transport, before, enrollment, code, after = run.transport, run.before, run.enrollment, run.code, run.after
        self.assertEqual([(item['method'], item['path']) for item in transport.requests], [
            ('GET', SESSION_PATH), ('GET', INFO_PATH), ('POST', DISABLE_PATH), ('POST', ENROLL_PATH),
            ('POST', ACTIVATE_PATH), ('GET', INFO_PATH)])
        self.assertEqual([item['body'] and json.loads(item['body']) for item in transport.requests], [
            None, None, {'factor_id': OLD_FACTOR}, {'factor_type': 'totp'},
            {'code': code, 'factor_type': 'totp', 'session_id': ENROLL_SESSION}, None])
        self.assertEqual(transport.steps, [])
        for request in transport.requests[1:]:
            self.assert_bearer(request, request['method'], request['path'])
        self.assertTrue(before.enabled)
        self.assertEqual(before.active_factor_id, OLD_FACTOR)
        self.assertEqual((enrollment.secret, enrollment.session_id, enrollment.factor_id),
                         (NEW_SECRET, ENROLL_SESSION, NEW_FACTOR))
        self.assertRegex(code, r'\A[0-9]{6}\Z')
        self.assertTrue(after.enabled)
        self.assertEqual(list(after.totp_factor_ids), [NEW_FACTOR])
        # Only a code derived from the new key leaves; the key itself is never part of a request.
        self.assertNotIn(NEW_SECRET, repr(transport.requests))
        # The access token stays inside the client, and nothing a call hands back prints the new key.
        self.assertNotIn(TOKEN, repr(run.returned))
        self.assertNotIn(NEW_SECRET, repr(run.returned))

    async def test_header_dicts_are_emptied_after_every_call(self):
        transport = (await self.run_sequence()).transport
        self.assertEqual(len(transport.live_headers), 6)
        self.assertEqual(transport.live_headers, [{}] * 6)
        # ... while the transport did see the bearer at the moment of each request.
        self.assertEqual([item['headers'].get('authorization') for item in transport.requests],
                         [None] + ['Bearer ' + TOKEN] * 5)

    async def test_header_dicts_are_emptied_when_the_call_fails(self):
        failures = (MfaTransportError(), (500, HOSTILE_BODY), (403, HOSTILE_BODY), (200, HOSTILE_PAGE),
                    RuntimeError('broken transport'), asyncio.CancelledError())
        for step in failures:
            label = type(step).__name__ if isinstance(step, BaseException) else step[0]
            for operation in OPERATIONS[1:]:
                with self.subTest(operation=operation, step=label):
                    client, transport = await opened_client(step)
                    try:
                        await bearer_calls(client)[operation]()
                    except (Exception, asyncio.CancelledError):
                        pass
                    else:
                        self.fail('the call cannot succeed')
                    self.assertEqual(len(transport.requests), 2)
                    self.assertEqual(transport.requests[1]['headers'].get('authorization'), 'Bearer ' + TOKEN)
                    self.assertEqual(transport.live_headers, [{}, {}])

    async def test_disable_without_a_factor_id_sends_nothing(self):
        for factor_id in ('', '   '):
            with self.subTest(factor_id=factor_id):
                client, transport = await opened_client()
                with self.assertRaises(MfaError) as caught:
                    await client.disable(factor_id)
                self.assertEqual(caught.exception.outcome, 'rejected')
                self.assertEqual(len(transport.requests), 1)

    async def test_nothing_is_logged_or_printed(self):
        records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(f'{record.getMessage()} {record.args!r} {record.exc_info!r}')

        root, handler, printed = logging.getLogger(), Capture(level=logging.DEBUG), io.StringIO()
        previous = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        try:
            with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(printed):
                transport = (await self.run_sequence()).transport
                for operation in OPERATIONS:
                    for step in ((400, HOSTILE_BODY), (500, HOSTILE_PAGE), (200, HOSTILE_PAGE), MfaTransportError()):
                        await self.failure(operation, step, 'rejected' if step == (400, HOSTILE_BODY) else 'unknown')
        finally:
            root.removeHandler(handler)
            root.setLevel(previous)
        self.assertEqual(len(transport.requests), 6)
        output = '\n'.join(records) + printed.getvalue()
        for value in FORBIDDEN:
            self.assertNotIn(value, output)


class SessionIdentityTests(ClientCase):
    async def open_with(self, body, expected_email=EMAIL):
        transport = ScriptedTransport((200, body))
        client = ChatGPTMfaClient(transport, expected_email=expected_email)
        try:
            await client.open_session()
        except MfaError as exc:
            return exc, client, transport
        return None, client, transport

    async def assert_opened(self, body, *, token, expected_email=EMAIL):
        error, client, transport = await self.open_with(body, expected_email)
        self.assertIsNone(error, error and f'refused as {error.code}')
        self.assertEqual(transport.live_headers, [{}])
        transport.steps.append((200, json.dumps({'mfa_enabled': False})))
        await client.state()
        self.assertEqual(transport.requests[1]['headers'].get('authorization'), 'Bearer ' + token)

    async def assert_refused(self, body, code, *, expected_email=EMAIL, secrets=()):
        error, client, transport = await self.open_with(body, expected_email)
        self.assertIsNotNone(error, 'the session was accepted')
        self.assertEqual((error.code, error.outcome), (code, 'rejected'))
        self.assertTrue(error.rejected)
        self.assert_no_leak(error, *secrets)
        # Only the session read left, and no bearer call can follow it.
        self.assertEqual([item['path'] for item in transport.requests], [SESSION_PATH])
        self.assertEqual(transport.live_headers, [{}])
        await self.assert_session_missing(client, transport)

    def test_fixture_tokens_carry_the_claims_the_tests_rely_on(self):
        claims = jwt_parser.decode_token(TOKEN)
        self.assertEqual((claims['email'], claims[PROFILE_CLAIM]['email']), (EMAIL, EMAIL))
        anonymous = jwt_parser.decode_token(ANONYMOUS_TOKEN)
        self.assertNotIn('email', anonymous)
        self.assertNotIn(PROFILE_CLAIM, anonymous)

    async def test_matching_identity_in_every_source_opens_the_session(self):
        await self.assert_opened(session_body(), token=TOKEN)
        ordinary = access_token(padding='p' * 3000)  # about the size of a real access token
        await self.assert_opened(session_body(token=ordinary), token=ordinary)

    async def test_email_comparison_ignores_case(self):
        token = access_token(claim_email='MEMBER@example.com', profile_email='Member@EXAMPLE.com')
        body = session_body(user_email='member@Example.COM', token=token)
        for expected in ('Member@Example.Com', EMAIL, EMAIL.upper()):
            with self.subTest(expected=expected):
                await self.assert_opened(body, token=token, expected_email=expected)

    async def test_one_matching_source_is_enough(self):
        for index, source in enumerate(SOURCES):
            with self.subTest(source=source):
                emails = [None, None, None]
                emails[index] = EMAIL
                body, token = identity_body(emails)
                await self.assert_opened(body, token=token)

    async def test_mismatch_in_any_source_is_refused(self):
        others = (OTHER_EMAIL, 'member@example.com.evil.test', 'xmember@example.com', 'member@example.co', 'member')
        for other in others:
            for index, source in enumerate(SOURCES):
                for rest in (EMAIL, None):  # the other two sources match, or are absent
                    with self.subTest(source=source, other=other, rest=rest):
                        emails = [rest, rest, rest]
                        emails[index] = other
                        body, token = identity_body(emails)
                        await self.assert_refused(body, 'session_identity_mismatch',
                                                  secrets=(token, token.split('.')[1]))

    async def test_session_without_any_email_is_refused(self):
        bodies = {
            'no email in any source': session_body(user_email=None, token=ANONYMOUS_TOKEN),
            'no user object': json.dumps({'accessToken': ANONYMOUS_TOKEN}),
            'null user': json.dumps({'user': None, 'accessToken': ANONYMOUS_TOKEN}),
            'text user': json.dumps({'user': 'user-fixture', 'accessToken': ANONYMOUS_TOKEN}),
            'list user': json.dumps({'user': [{'id': 'user-fixture'}], 'accessToken': ANONYMOUS_TOKEN}),
            'text profile claim': session_body(user_email=None, token=access_token(
                claim_email=None, profile_email=None, **{PROFILE_CLAIM: 'profile-as-text'})),
            'blank emails': session_body(user_email='', token=access_token(claim_email='', profile_email='')),
            'whitespace emails': session_body(user_email='  ', token=access_token(claim_email=' ', profile_email=' ')),
            'opaque token': session_body(user_email=None, token='opaque-synthetic-session-token'),
        }
        for name, body in bodies.items():
            with self.subTest(case=name):
                await self.assert_refused(body, 'session_identity_mismatch', secrets=(ANONYMOUS_TOKEN,))

    async def test_client_without_an_expected_email_never_opens(self):
        blank_token = access_token(claim_email='', profile_email='')
        bodies = (session_body(), session_body(user_email=None, token=ANONYMOUS_TOKEN),
                  session_body(user_email='', token=blank_token))
        for expected in ('', '   '):
            for body in bodies:
                with self.subTest(expected=expected, body=body[:60]):
                    await self.assert_refused(body, 'session_identity_mismatch', expected_email=expected,
                                              secrets=(TOKEN, ANONYMOUS_TOKEN, blank_token))

    async def test_missing_token_is_session_missing(self):
        user = {'id': 'user-fixture', 'email': EMAIL}
        bodies = ('{}', '', json.dumps({'user': user}), json.dumps({'user': user, 'accessToken': None}),
                  json.dumps({'user': user, 'accessToken': ''}), json.dumps({'user': user, 'accessToken': 12345}),
                  json.dumps({'user': user, 'accessToken': [TOKEN]}),
                  json.dumps({'user': user, 'accessToken': {'value': TOKEN}}),
                  json.dumps({'user': user, 'accessToken': True}),
                  json.dumps({'user': user, 'accessToken': '', 'access_token': ''}))
        for body in bodies:
            with self.subTest(body=body[:80]):
                await self.assert_refused(body, 'session_missing', secrets=(TOKEN,))

    async def test_oversized_token_is_session_missing(self):
        for size in (20000, 200000):
            with self.subTest(size=size):
                token = access_token(padding='p' * size)
                self.assertGreater(len(token), size)
                self.assertEqual(jwt_parser.decode_token(token)['email'], EMAIL)  # otherwise a matching identity
                await self.assert_refused(session_body(token=token), 'session_missing', secrets=(token,))

    async def test_token_with_whitespace_or_control_characters_is_session_missing(self):
        middle = len(TOKEN) // 2
        for filler in (' ', '\t', '\n', '\r\n', '\x00', '\x1f'):
            with self.subTest(filler=filler):
                token = TOKEN[:middle] + filler + TOKEN[middle:]
                await self.assert_refused(session_body(token=token), 'session_missing',
                                          secrets=(TOKEN[:middle], TOKEN[middle:]))
        for blank in (' ', '   ', '\n', '\t \r\n'):
            with self.subTest(blank=blank):
                await self.assert_refused(session_body(token=blank), 'session_missing')

    async def test_access_token_alias_is_accepted(self):
        await self.assert_opened(json.dumps({'user': {'email': EMAIL}, 'access_token': TOKEN}), token=TOKEN)

    async def test_a_token_of_another_identity_is_never_used_as_bearer(self):
        foreign = access_token(claim_email=OTHER_EMAIL, profile_email=OTHER_EMAIL)
        for tokens in ({'accessToken': TOKEN, 'access_token': foreign}, {'accessToken': foreign, 'access_token': TOKEN},
                       {'accessToken': foreign}, {'access_token': foreign}):
            label = {name: 'foreign' if value is foreign else 'own' for name, value in tokens.items()}
            with self.subTest(tokens=label):
                body = json.dumps({'user': {'id': 'user-fixture', 'email': EMAIL}, **tokens})
                error, client, transport = await self.open_with(body)
                if error is None:
                    # Accepting is only acceptable with the token whose own claims were checked.
                    transport.steps.append((200, json.dumps({'mfa_enabled': False})))
                    await client.state()
                    self.assertEqual(transport.requests[1]['headers'].get('authorization'), 'Bearer ' + TOKEN)
                else:
                    self.assertEqual((error.code, error.outcome), ('session_identity_mismatch', 'rejected'))
                    self.assert_no_leak(error, foreign, TOKEN)
                    await self.assert_session_missing(client, transport)
                self.assertNotIn(foreign, repr([item['headers'] for item in transport.requests]))

    async def test_calls_before_open_session_fail_without_sending(self):
        transport = ScriptedTransport()
        client = ChatGPTMfaClient(transport, expected_email=EMAIL)
        await self.assert_session_missing(client, transport)
        self.assertEqual(transport.requests, [])

    async def test_close_drops_the_token(self):
        client, transport = await opened_client((200, json.dumps(ACCEPTED['info'])))
        await client.state()  # the session works until it is closed
        self.assertEqual(len(transport.requests), 2)
        client.close()
        await self.assert_session_missing(client, transport)
        self.assertEqual(len(transport.requests), 2)
        self.assertNotIn(TOKEN, repr(getattr(client, '__dict__', '')))
        self.assertNotIn(TOKEN, repr(client) + str(client))


class StateParsingTests(ClientCase):
    async def state_of(self, payload):
        return await self.success('info', (200, json.dumps(payload)))

    async def test_enabled_account_lists_its_totp_factors_in_order(self):
        state = await self.state_of({
            'mfa_enabled': True, 'mfa_enabled_v2': True, 'native_default_factor_id': 'factor-b',
            'factors': {'totp': [{'id': 'factor-a', 'factor_type': 'totp'}, {'id': 'factor-b'}],
                        'sms': [{'id': 'factor-sms'}]}})
        self.assertTrue(state.enabled)
        self.assertEqual(list(state.totp_factor_ids), ['factor-a', 'factor-b'])
        self.assertEqual(state.active_factor_id, 'factor-a')

    async def test_duplicate_factor_ids_are_listed_once(self):
        state = await self.state_of({'mfa_enabled': True, 'factors': {'totp': [
            {'id': 'factor-a'}, {'id': 'factor-b'}, {'id': 'factor-a'}, {'id': 'factor-b'}, {'id': 'factor-c'}]}})
        self.assertEqual(list(state.totp_factor_ids), ['factor-a', 'factor-b', 'factor-c'])
        self.assertEqual(state.active_factor_id, 'factor-a')

    async def test_default_factor_is_the_fallback_active_factor(self):
        for factors in (ABSENT, None, {}, {'totp': []}, {'totp': None}, {'sms': [{'id': 'factor-sms'}]}):
            with self.subTest(factors=factors):
                payload = {'mfa_enabled': True, 'native_default_factor_id': 'factor-default'}
                if factors is not ABSENT:
                    payload['factors'] = factors
                state = await self.state_of(payload)
                self.assertTrue(state.enabled)
                self.assertEqual(list(state.totp_factor_ids), [])
                self.assertEqual(state.active_factor_id, 'factor-default')
        listed = await self.state_of({'mfa_enabled': True, 'native_default_factor_id': 'factor-default',
                                      'factors': {'totp': [{'id': 'factor-a'}]}})
        self.assertEqual(listed.active_factor_id, 'factor-a')
        bare = await self.state_of({'mfa_enabled': True})
        self.assertTrue(bare.enabled)
        self.assertEqual(bare.active_factor_id, '')

    async def test_mfa_enabled_v2_counts_as_enabled(self):
        for payload in ({'mfa_enabled_v2': True}, {'mfa_enabled': False, 'mfa_enabled_v2': True},
                        {'mfa_enabled': True, 'mfa_enabled_v2': False}, {'mfa_enabled': True}):
            with self.subTest(payload=payload):
                self.assertTrue((await self.state_of(payload)).enabled)

    async def test_recognised_disabled_shapes_read_as_disabled(self):
        for payload in ({'mfa_enabled': False}, {'mfa_enabled_v2': False},
                        {'mfa_enabled': False, 'mfa_enabled_v2': False, 'factors': {'totp': []},
                         'native_default_factor_id': None}):
            with self.subTest(payload=payload):
                state = await self.state_of(payload)
                self.assertFalse(state.enabled)
                self.assertEqual(list(state.totp_factor_ids), [])
                self.assertEqual(state.active_factor_id, '')
        # "Enabled" is what the flags say: a factor that is merely listed (for instance an enrolment
        # that was never activated) does not turn 2FA on.
        listed = await self.state_of({'mfa_enabled': False, 'mfa_enabled_v2': False,
                                      'factors': {'totp': [{'id': NEW_FACTOR}]}})
        self.assertFalse(listed.enabled)
        self.assertEqual(list(listed.totp_factor_ids), [NEW_FACTOR])

    async def test_unrecognised_shape_is_never_read_as_disabled(self):
        bodies = ('{}', '', '{"unexpected": true}', '{"detail": "Not Found"}', '{"data": {"mfa_enabled": true}}',
                  '{"MFA_ENABLED": true}', '{"native_default_factor_id": "factor-default"}')
        for status in (200, 204):
            for text in bodies:
                with self.subTest(status=status, text=text):
                    error = await self.failure('info', (status, text), 'unknown')
                    self.assertEqual(error.code, 'info_invalid_response')
                    self.assertFalse(error.rejected)

    async def test_garbage_factor_entries_are_ignored(self):
        garbage = [None, 'factor-as-text', [], {}, {'id': None}, {'id': ''}, {'id': '   '},
                   {'id': {'nested': 'factor-x'}}, {'id': ['factor-y']}, {'id': True}, {'id': 'line\nbreak'},
                   {'id': 'nul\x00byte'}, {'id': 'x' * 5000}, {'name': 'entry without id'}]
        state = await self.state_of({'mfa_enabled': True,
                                     'factors': {'totp': [*garbage, {'id': 'factor-good'}, *garbage]}})
        self.assertTrue(state.enabled)
        self.assertEqual(list(state.totp_factor_ids), ['factor-good'])
        self.assertEqual(state.active_factor_id, 'factor-good')
        for factors in ('nope', [], 17, {'totp': 'nope'}, {'totp': {'id': 'factor-x'}}, {'totp': 17}):
            with self.subTest(factors=factors):
                state = await self.state_of({'mfa_enabled': True, 'factors': factors})
                self.assertTrue(state.enabled)
                self.assertEqual(list(state.totp_factor_ids), [])
                self.assertEqual(state.active_factor_id, '')
        for default in (None, '', '   ', {'id': 'factor-x'}, ['factor-x'], True, 'line\nbreak', 'x' * 5000):
            with self.subTest(default=default):
                state = await self.state_of({'mfa_enabled': True, 'native_default_factor_id': default})
                self.assertEqual(state.active_factor_id, '')


class EnrollTests(ClientCase):
    async def test_enrollment_returns_key_session_and_factor(self):
        enrollment = await self.success('enroll', (200, enroll_body()))
        self.assertEqual((enrollment.secret, enrollment.session_id, enrollment.factor_id),
                         (NEW_SECRET, ENROLL_SESSION, NEW_FACTOR))

    async def test_returned_key_is_canonical_base32(self):
        cases = {
            'krsxg5dsnfxgoidbkrsxg5dsnfxgoidb': NEW_SECRET,
            'KRSX G5DS NFXG OIDB KRSX G5DS NFXG OIDB': NEW_SECRET,
            'krsx-g5ds-nfxg-oidb-krsx-g5ds-nfxg-oidb': NEW_SECRET,
            '\tKRSXG5DSNFXGOIDBKRSXG5DSNFXGOIDB\n': NEW_SECRET,
            PADDED_SECRET: PADDED_SECRET.rstrip('='),
        }
        for raw, canonical in cases.items():
            with self.subTest(raw=raw):
                enrollment = await self.success('enroll', (200, enroll_body(secret=raw)))
                self.assertEqual(enrollment.secret, canonical)
                # The stored key yields exactly the codes of the key the service issued.
                self.assertEqual(generate_totp(enrollment.secret, timestamp=59), generate_totp(raw, timestamp=59))

    async def test_missing_factor_id_is_tolerated(self):
        for factor in (ABSENT, None, {}, {'id': None}, {'id': ''}, {'factor_type': 'totp'}, [], 17):
            with self.subTest(factor=factor):
                payload = {'secret': NEW_SECRET, 'session_id': ENROLL_SESSION}
                if factor is not ABSENT:
                    payload['factor'] = factor
                enrollment = await self.success('enroll', (200, json.dumps(payload)))
                self.assertEqual((enrollment.secret, enrollment.session_id), (NEW_SECRET, ENROLL_SESSION))
                self.assertEqual(enrollment.factor_id, '')

    async def test_unusable_key_is_an_unknown_outcome(self):
        secrets = (ABSENT, None, '', '   ', 12345678901234567890, ['KRSXG5DSNFXGOIDB'], {'value': NEW_SECRET},
                   '123456', 'JBSWY3DP', 'JBSWY3DPEHPK3PX', 'KRSXG5DSNFXGOID0', 'KRSXG5DSNFXGOID1',
                   'KRSXG5DSNFXGOID8', 'KRSXG5DSNFXGOIDB!', 'not a key! ' + BODY_MARKER)
        for secret in secrets:
            with self.subTest(secret=secret):
                payload = {'session_id': ENROLL_SESSION, 'factor': {'id': NEW_FACTOR}}
                if secret is not ABSENT:
                    payload['secret'] = secret
                error = await self.failure('enroll', (200, json.dumps(payload)), 'unknown')
                self.assertEqual(error.code, 'enroll_invalid_response')
                self.assertFalse(error.rejected)
                self.assert_no_leak(error, NEW_SECRET, ENROLL_SESSION, BODY_MARKER,
                                    *([secret.strip()] if isinstance(secret, str) and secret.strip() else []))

    async def test_missing_enrolment_session_is_an_unknown_outcome(self):
        # Whole numbers are coerced like the reference's String(value); other shapes are unusable.
        for session_id in (ABSENT, None, '', '   ', True, ['x'], {'id': ENROLL_SESSION}):
            with self.subTest(session_id=session_id):
                payload = {'secret': NEW_SECRET, 'factor': {'id': NEW_FACTOR}}
                if session_id is not ABSENT:
                    payload['session_id'] = session_id
                error = await self.failure('enroll', (200, json.dumps(payload)), 'unknown')
                self.assertEqual(error.code, 'enroll_invalid_response')
                self.assertFalse(error.rejected)
                self.assert_no_leak(error, NEW_SECRET, ENROLL_SESSION)

    async def test_enrollment_object_does_not_print_the_key(self):
        enrollment = await self.success('enroll', (200, enroll_body()))
        for text in (repr(enrollment), str(enrollment), f'{enrollment}', '%s %r' % (enrollment, enrollment)):
            self.assertNotIn(NEW_SECRET, text)


class ClassificationTests(ClientCase):
    async def test_acknowledged_answers_are_accepted(self):
        for operation in OPERATIONS:
            for status in (200, 201, 299):
                with self.subTest(operation=operation, status=status):
                    await self.success(operation, (status, json.dumps(ACCEPTED[operation])))

    async def test_transport_failure_is_unknown(self):
        for operation in OPERATIONS:
            with self.subTest(operation=operation):
                error = await self.failure(operation, MfaTransportError(), 'unknown')
                self.assertFalse(error.status)
                self.assertEqual(error.remote_code, '')

    async def test_server_errors_are_unknown(self):
        for operation in OPERATIONS:
            for status in (500, 501, 502, 503, 504, 520, 524, 599):
                for text in (json.dumps(ACCEPTED[operation]), HOSTILE_BODY, '', None, '<html>bad gateway</html>'):
                    with self.subTest(operation=operation, status=status, text=text and text[:20]):
                        error = await self.failure(operation, (status, text), 'unknown')
                        self.assertEqual(error.status, status)

    async def test_success_status_with_unusable_body_is_unknown(self):
        bodies = (None, '[]', '[{"success": true}]', '"ok"', 'true', '42', 'null', HOSTILE_PAGE,
                  '{"truncated": ', '[' * 100000)
        for operation in OPERATIONS:
            for status in (200, 201, 204):
                for text in bodies:
                    with self.subTest(operation=operation, status=status, text=text and text[:20]):
                        error = await self.failure(operation, (status, text), 'unknown')
                        self.assertEqual(error.status, status)
                        self.assertEqual(error.remote_code, '')
                        self.assert_no_leak(error, *FORBIDDEN)

    async def test_success_status_with_error_or_success_false_is_rejected(self):
        members = ({'error': {'code': 'remote_failure', 'message': BODY_MARKER}}, {'error': {'message': BODY_MARKER}},
                   {'error': 'failure text ' + BODY_MARKER}, {'error': [BODY_MARKER]}, {'error': True}, {'error': 1},
                   {'success': False}, {'success': False, 'error': None})
        for operation in OPERATIONS:
            for member in members:
                for status in (200, 201):
                    with self.subTest(operation=operation, member=member, status=status):
                        step = (status, json.dumps({**ACCEPTED[operation], **member}))
                        error = await self.failure(operation, step, 'rejected')
                        self.assertEqual(error.status, status)
                        self.assert_no_leak(error, BODY_MARKER, NEW_SECRET)

    async def test_blank_error_member_is_not_a_rejection(self):
        members = ({'error': None}, {'error': ''}, {'error': False}, {'error': 0}, {'success': True},
                   {'success': True, 'error': None})
        for operation in OPERATIONS:
            for member in members:
                with self.subTest(operation=operation, member=member):
                    await self.success(operation, (200, json.dumps({**ACCEPTED[operation], **member})))

    async def test_empty_error_container_is_still_a_rejection(self):
        # The ported flow (gpt-auth-bridge fetchChatGptJson: `!response.ok || payload?.error || ...`) refuses
        # every present "error" member that is not null/false/0/""; an empty object or list is such a member
        # and must not be read as an acknowledged change.
        for member in ({}, []):
            for operation in OPERATIONS:
                with self.subTest(operation=operation, error=member):
                    step = (200, json.dumps({**ACCEPTED[operation], 'error': member}))
                    error = await self.failure(operation, step, 'rejected')
                    self.assertEqual(error.status, 200)

    async def test_401_is_session_rejected(self):
        for operation in OPERATIONS:
            for text in (json.dumps(ACCEPTED[operation]), HOSTILE_BODY, HOSTILE_PAGE, '', None):
                with self.subTest(operation=operation, text=text and text[:20]):
                    error = await self.failure(operation, (401, text), 'rejected')
                    self.assertEqual((error.code, error.status), ('session_rejected', 401))

    async def test_429_is_rate_limited(self):
        for operation in OPERATIONS:
            for text in (json.dumps(ACCEPTED[operation]), HOSTILE_BODY, HOSTILE_PAGE, '', None):
                with self.subTest(operation=operation, text=text and text[:20]):
                    error = await self.failure(operation, (429, text), 'rejected')
                    self.assertEqual((error.code, error.status), ('rate_limited', 429))

    async def test_redirects_and_client_errors_are_rejected(self):
        statuses = (0, 301, 302, 303, 307, 308, 400, 402, 403, 404, 405, 409, 410, 415, 422, 423, 451)
        for operation in OPERATIONS:
            for status in statuses:
                for text in (json.dumps(ACCEPTED[operation]), HOSTILE_BODY, HOSTILE_PAGE, '', None):
                    with self.subTest(operation=operation, status=status, text=text and text[:20]):
                        error = await self.failure(operation, (status, text), 'rejected')
                        self.assertEqual(error.status, status)

    async def test_empty_body_acknowledges_disable_and_activate(self):
        # 204 No Content is an explicit acknowledgement; any other empty 2xx is left to the status read.
        for operation in ('disable', 'activate'):
            for step in ((204, ''), (200, '{}')):
                with self.subTest(operation=operation, step=step):
                    await self.success(operation, step)
            for step in ((200, ''), (202, ''), (200, '   ')):
                with self.subTest(operation=operation, step=step):
                    error = await self.failure(operation, step, 'unknown')
                    self.assertEqual(error.code, operation + '_invalid_response')

    async def test_non_integer_status_is_unknown(self):
        for status in (None, '200', '204', 200.0, 204.5, [200], {'status': 200}, True, False):
            for operation in OPERATIONS:
                with self.subTest(operation=operation, status=status):
                    error = await self.failure(operation, (status, json.dumps(ACCEPTED[operation])), 'unknown')
                    self.assertFalse(error.status)

    async def test_remote_code_sources_and_precedence(self):
        cases = (
            ({'error': {'code': 'invalid_totp_code', 'message': BODY_MARKER}}, 'invalid_totp_code'),
            ({'detail': {'code': 'mfa_challenge_failed', 'msg': BODY_MARKER}}, 'mfa_challenge_failed'),
            ({'code': 'enrollment_expired', 'message': BODY_MARKER}, 'enrollment_expired'),
            ({'error': {'code': 'from_error'}, 'detail': {'code': 'from_detail'}, 'code': 'from_top'}, 'from_error'),
            ({'detail': {'code': 'from_detail'}, 'code': 'from_top'}, 'from_detail'),
            ({'error': 'text only', 'detail': 'text only', 'code': 'from_top'}, 'from_top'),
            ({'error': {'code': 'Mixed_Case_123'}}, 'Mixed_Case_123'),
            ({'error': {'code': 'a'}}, 'a'),
            ({'error': {'code': 'x' * 80}}, 'x' * 80),
            ({'error': {'message': BODY_MARKER}, 'detail': BODY_MARKER}, ''),
            ({'message': BODY_MARKER}, ''),
        )
        outcomes = {400: 'rejected', 401: 'rejected', 403: 'rejected', 429: 'rejected', 500: 'unknown', 503: 'unknown'}
        for payload, expected in cases:
            for status, outcome in outcomes.items():
                for operation in ('session', 'disable', 'activate'):
                    with self.subTest(payload=payload, status=status, operation=operation):
                        error = await self.failure(operation, (status, json.dumps(payload)), outcome)
                        self.assertEqual(error.remote_code, expected)
                        self.assert_no_leak(error, BODY_MARKER)
        # On an answered 2xx the code of the refusal is kept as well.
        for payload, expected in (({'error': {'code': 'invalid_totp_code'}}, 'invalid_totp_code'),
                                  ({'success': False, 'detail': {'code': 'from_detail'}}, 'from_detail'),
                                  ({'success': False, 'code': 'from_top'}, 'from_top')):
            with self.subTest(payload=payload):
                error = await self.failure('activate', (200, json.dumps(payload)), 'rejected')
                self.assertEqual(error.remote_code, expected)

    async def test_unsanitary_remote_codes_are_dropped(self):
        unsanitary = ('has space', 'has-hyphen', 'dot.ted', 'semi;colon', 'slash/ed', 'new\nline',
                      'trailing_newline\n', 'tab\tbed', 'ünïcödé', 'ｆｕｌｌｗｉｄｔｈ', '<script>alert(1)</script>', '',
                      'x' * 81, 'x' * 5000, TOKEN, BODY_MARKER, {'nested': 'object'}, ['list'], None)
        shapes = (lambda value: {'error': {'code': value}}, lambda value: {'detail': {'code': value}},
                  lambda value: {'code': value})
        for value in unsanitary:
            for index, shape in enumerate(shapes):
                with self.subTest(value=value if not isinstance(value, str) else value[:30], shape=index):
                    error = await self.failure('activate', (400, json.dumps(shape(value))), 'rejected')
                    self.assertEqual(error.remote_code, '')
                    if isinstance(value, str) and value.strip():
                        self.assert_no_leak(error, value, value.strip())
        # A code of another JSON type is either dropped or reduced to the same safe alphabet (checked by failure()).
        for value in (12345, 0, True, 1.5):
            with self.subTest(value=value):
                await self.failure('activate', (400, json.dumps({'error': {'code': value}})), 'rejected')
        # An unusable first candidate never surfaces, whatever the client does with the next one.
        error = await self.failure('activate', (400, json.dumps(
            {'error': {'code': 'not usable ' + BODY_MARKER}, 'detail': {'code': 'from_detail'}})), 'rejected')
        self.assertIn(error.remote_code, ('', 'from_detail'))
        self.assert_no_leak(error, BODY_MARKER)

    async def test_errors_never_carry_token_key_code_or_body_text(self):
        for operation in OPERATIONS:
            for status in (0, 200, 302, 400, 401, 403, 404, 429, 500, 503):
                codes = set()
                for text in (HOSTILE_BODY, HOSTILE_PAGE):
                    with self.subTest(operation=operation, status=status, json=text is HOSTILE_BODY):
                        unknown = status >= 500 or (status == 200 and text is HOSTILE_PAGE)
                        error = await self.failure(operation, (status, text), 'unknown' if unknown else 'rejected')
                        self.assert_no_leak(error, *FORBIDDEN)
                        self.assertEqual(error.remote_code, 'remote_failure' if text is HOSTILE_BODY else '')
                        codes.add(error.code)
                if status != 200:
                    # A fixed code: it depends on the call and the status class, never on what the body said.
                    self.assertEqual(len(codes), 1, codes)
        # Failures found locally after an answer was read.
        local = (('enroll', enroll_body(secret='not a key! ' + BODY_MARKER), 'unknown'),
                 ('enroll', enroll_body(session_id=''), 'unknown'),
                 ('info', json.dumps({'unexpected': BODY_MARKER, 'secret': NEW_SECRET, 'token': TOKEN}), 'unknown'),
                 ('session', session_body(user_email=OTHER_EMAIL, note=BODY_MARKER), 'rejected'),
                 ('session', session_body(token='white space ' + TOKEN, note=BODY_MARKER), 'rejected'))
        for operation, text, outcome in local:
            with self.subTest(operation=operation, text=text[:40]):
                error = await self.failure(operation, (200, text), outcome)
                self.assert_no_leak(error, *FORBIDDEN)
        # Whatever the transport says about its own failure stays out of the client's error.
        for operation in OPERATIONS:
            with self.subTest(operation=operation, transport='failure text'):
                talkative = MfaTransportError(f'{BODY_MARKER} {TOKEN} {NEW_SECRET}')
                error = await self.failure(operation, talkative, 'unknown')
                self.assert_no_leak(error, *FORBIDDEN)


if __name__ == '__main__':
    unittest.main()
