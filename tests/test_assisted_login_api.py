"""Authenticated endpoints, encrypted backup and the reset-2FA surface, all isolated and synthetic.

Nothing here opens a browser or a connection: the "official service" is an in-memory
object behind the MFA transport contract and the browser driver is replaced by a stub.
"""
import asyncio
import base64
import hashlib
import hmac
import inspect
import json
import logging
import re
import struct
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch
from tests.helpers import make_client

from sqlalchemy import select

from app.application import totp_reset
from app.application.operations import operation_store
from app.application.tokens import decrypt_secret, encrypt_secret
from app.core.crypto import TokenCipher, token_cipher
from app.integrations.openai.mfa import ChatGPTMfaClient, MfaTransportError
from app.persistence.models.identity import Account, Workspace
from app.persistence.models.operations import Operation
from app.persistence.models.settings import SystemSetting

EMAIL = 'fixture@example.com'
PASSWORD = 'fixture-private-password-never-log'
OLD_SECRET = 'JBSWY3DPEHPK3PXP'                      # key the account used before the reset
NEW_SECRET = 'KRSXG5DSNFXGOIDBKRSXG5DSNFXGOIDB'      # key the synthetic official service enrols
MANUAL_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'   # key a user backs up by hand
REMOTE_NOTE = 'REMOTE-BODY-TEXT-NEVER-STORED'        # free text of an official error body

START = '/api/assisted-login/start'
BACKUP = '/api/assisted-login/totp-backup'
BACKUP_REVEAL = '/api/assisted-login/totp-backup/reveal'
STATUS = '/api/assisted-login/totp-reset/status'
REVEAL = '/api/assisted-login/totp-reset/reveal'
ABANDON = '/api/assisted-login/totp-reset/abandon'
DRIVER_MODULE = 'app.integrations.openai.browser.assisted_login'

# The official requests of the contract, as (method, path).
SESSION = ('GET', '/api/auth/session')
INFO = ('GET', '/backend-api/accounts/mfa_info')
DISABLE = ('POST', '/backend-api/accounts/mfa/user/disable_in_house')
ENROLL = ('POST', '/backend-api/accounts/mfa/enroll')
ACTIVATE = ('POST', '/backend-api/accounts/mfa/user/activate_enrollment')

LOST = 'request lost'        # no response, and the service never acted
LOST_AFTER = 'answer lost'   # the service acted, but its response never arrived
REFUSAL = (400, json.dumps({'detail': {'code': 'invalid_code', 'message': REMOTE_NOTE}}))
# Where a real run has to be interrupted to leave a record in each phase.
INTERRUPTED_AT = {
    'preparing': {DISABLE: [LOST]},          # the outcome of "disable" is unknown
    'prepared': {ACTIVATE: [REFUSAL]},       # the activation is answered with a refusal
    'activating': {ACTIVATE: [LOST]},        # the outcome of the activation is unknown
    'activated': {INFO: [None, LOST]},       # activation acknowledged, the confirming read fails
    'confirmed': {},
}


def _segment(value):
    raw = value if isinstance(value, bytes) else json.dumps(value, separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def _synthetic_jwt(email):
    """Unsigned fixture token; app.core.jwt decodes without verifying."""
    claims = {'email': email, 'https://api.openai.com/profile': {'email': email}}
    return '.'.join((_segment({'alg': 'HS256', 'typ': 'JWT'}), _segment(claims),
                     _segment(b'synthetic-signature-never-verified')))


def _totp(secret, moment):
    """RFC 6238 (SHA-1, six digits, 30 s), written out here so the stub does not trust the code under test."""
    key = base64.b32decode(secret + '=' * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack('>Q', int(moment // 30)), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return '%06d' % ((struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000)


class OfficialService:
    """In-memory stand-in for the signed-in chatgpt.com page.

    Implements the transport contract ``request(method, path, *, headers, body) ->
    (status, text)`` and keeps the state a real service keeps: ``disable`` removes a
    factor, ``enroll`` hands out one key with a session, and only a six-digit code
    derived from that key and sent with that session makes the new factor live.
    """

    def __init__(self, email, *, names_factor=True):
        self.email = email
        self.token = _synthetic_jwt(email)
        self.factors = ['factor-old']
        self.names_factor = names_factor   # whether enrol answers with the id of the new factor
        self.pending = None
        self.enrolled = 0
        self.plan = {}                     # (method, path) -> outcomes consumed before answering normally
        self.on_call = {}                  # (method, path) -> callback run when that request arrives
        self.calls = []
        self.activations = []              # (session_id, code) of every activation request received

    async def request(self, method, path, *, headers, body):
        call = (method, path)
        self.calls.append(call)
        if call in self.on_call:
            self.on_call[call]()
        sent = {str(name).lower(): value for name, value in headers.items()}
        authorized = sent.get('authorization') == 'Bearer ' + self.token
        payload = json.loads(body) if body else {}
        if call == ACTIVATE:
            self.activations.append((payload.get('session_id'), payload.get('code')))
        planned = self.plan.get(call)
        outcome = planned.pop(0) if planned else None
        if outcome == LOST:
            raise MfaTransportError()
        if isinstance(outcome, tuple):
            return outcome
        answer = self._answer(call, authorized, payload)
        if outcome == LOST_AFTER:
            raise MfaTransportError()
        return answer

    def _answer(self, call, authorized, payload):
        if call == SESSION:
            return 200, json.dumps({'accessToken': self.token, 'user': {'email': self.email}})
        if not authorized:
            return 401, json.dumps({'detail': {'code': 'token_invalid'}})
        if call == INFO:
            return 200, json.dumps({'mfa_enabled': bool(self.factors),
                                    'factors': {'totp': [{'id': item} for item in self.factors]}})
        if call == DISABLE and payload.get('factor_id') in self.factors:
            self.factors.remove(payload['factor_id'])
            return 200, json.dumps({'success': True})
        if call == ENROLL and payload.get('factor_type') == 'totp':
            self.enrolled += 1
            self.pending = ('enrol-session-%d' % self.enrolled, 'factor-new-%d' % self.enrolled)
            answer = {'secret': NEW_SECRET, 'session_id': self.pending[0]}
            if self.names_factor:
                answer['factor'] = {'id': self.pending[1]}
            return 200, json.dumps(answer)
        now = time.time()
        if (call == ACTIVATE and self.pending and payload.get('factor_type') == 'totp'
                and payload.get('session_id') == self.pending[0]
                and payload.get('code') in {_totp(NEW_SECRET, now + drift) for drift in (-30, 0, 30)}):
            self.factors.append(self.pending[1])
            self.pending = None
            return 200, json.dumps({'success': True})
        return 400, json.dumps({'detail': {'code': 'invalid_request'}})


class _LogCapture(logging.Handler):
    """What the process logs while a test runs, tracebacks included."""

    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        try:
            self.lines.append(self.format(record))
        except Exception:  # noqa: BLE001 - a malformed record is still evidence
            self.lines.append(str(record.msg))


class AssistedApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.context = make_client(Path(self.tmp.name))
        self.client = self.context.__enter__()

    def tearDown(self):
        self.context.__exit__(None, None, None)
        self.tmp.cleanup()

    def login(self):
        self.assertEqual(self.client.post('/auth/login', json={'username':'hixz12','password':'test-password'}).status_code, 200)

    def test_authentication_and_secret_input_validation(self):
        response = self.client.get('/api/assisted-login/capabilities')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers.get('cache-control'), 'no-store')
        self.login()
        sentinel = 'SYNTHETIC-SECRET-NOT-FOR-ECHO'
        response = self.client.post('/api/assisted-login/start', json={'email':'invalid','password':sentinel})
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(sentinel, response.text)
        self.assertEqual(response.headers.get('cache-control'), 'no-store')
        with patch('app.application.assisted_login.start_assisted_login', AsyncMock()) as start:
            response = self.client.post('/api/assisted-login/start', json={'email':'test@example.com','password':sentinel}, headers={'origin':'https://testserver'})
            self.assertEqual(response.status_code, 403)
            start.assert_not_awaited()

    def test_explicit_login_dispatch_and_capabilities_are_honest(self):
        self.login()
        caps = self.client.get('/api/assisted-login/capabilities').json()
        # The reset is an automated MFA change performed by this program, and it says so.
        self.assertIs(caps['automatic_mfa_change'], True)
        self.assertIs(caps['totp_reset'], True)
        with patch('app.application.assisted_login.start_assisted_login', AsyncMock(return_value={'ok':True,'operation_id':'fixture'})) as start:
            response = self.client.post('/api/assisted-login/start', json={'email':'test@example.com','password':'fixture-password','action':'oauth'})
            self.assertEqual(response.status_code, 202)
            start.assert_awaited_once()
            self.assertNotIn('fixture-password', response.text)

    def test_backup_requires_confirmation_and_does_not_return_secret(self):
        self.login()
        secret = 'JBSWY3DPEHPK3PXP'
        payload = {'email':'fixture@example.com','secret':secret,'confirmed':False}
        response = self.client.post('/api/assisted-login/totp-backup', json=payload)
        self.assertEqual(response.status_code, 400)
        payload['confirmed'] = True
        response = self.client.post('/api/assisted-login/totp-backup', json=payload)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(secret, response.text)
        self.assertEqual(response.json()['verification'], 'user_reported')
        self.assertNotIn(secret.encode(), (Path(self.tmp.name)/'team48.db').read_bytes())
        response = self.client.post('/api/assisted-login/totp-backup/reveal', json={'email':'fixture@example.com'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['secret'], secret)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertIn('attachment', response.headers['content-disposition'])
        self.assertNotEqual(self.client.get('/api/assisted-login/totp-backup/reveal').status_code, 200)

    def test_wrong_email_and_bad_secret_never_read_or_overwrite_backup(self):
        self.login()
        response = self.client.post('/api/assisted-login/totp-backup/reveal', json={'email':'missing@example.com'})
        self.assertEqual(response.status_code, 404)
        response = self.client.post('/api/assisted-login/totp-backup', json={'email':'fixture@example.com','secret':'123456','confirmed':True})
        self.assertEqual(response.status_code, 400)

    def test_reset_start_passes_the_explicit_confirmation_through(self):
        self.login()
        fields = {'email': 'test@example.com', 'password': 'fixture-password', 'action': 'reset_totp'}
        accepted = AsyncMock(return_value={'ok': True, 'operation_id': 'fixture'})
        with patch('app.application.assisted_login.start_assisted_login', accepted) as start:
            # Leaving the field out is not a confirmation either: the service must see False.
            for extra, expected in (({'confirm_reset': True}, True), ({'confirm_reset': False}, False), ({}, False)):
                with self.subTest(sent=extra):
                    start.reset_mock()
                    response = self.client.post(START, json={**fields, **extra})
                    self.assertEqual(response.status_code, 202)
                    self.assertEqual(response.headers.get('cache-control'), 'no-store')
                    self.assertNotIn('fixture-password', response.text)
                    start.assert_awaited_once()
                    sent = start.await_args.kwargs
                    self.assertIs(sent['confirm_reset'], expected)
                    self.assertEqual(sent['action'], 'reset_totp')
                    self.assertEqual((sent['email'], sent['password']), ('test@example.com', 'fixture-password'))

    def test_reset_start_rejects_non_boolean_confirmation_and_unknown_actions(self):
        self.login()
        sentinel = 'SYNTHETIC-PASSWORD-NOT-FOR-ECHO'
        fields = {'email': 'test@example.com', 'password': sentinel, 'action': 'reset_totp'}
        with patch('app.application.assisted_login.start_assisted_login', AsyncMock(return_value={'ok': True})) as start:
            rejected = [{**fields, 'confirm_reset': value} for value in ('yes', 'true', 1, 0, None)]
            rejected += [{**fields, 'action': action, 'confirm_reset': True} for action in ('reset', 'disable_totp', 'change_mfa')]
            for payload in rejected:
                with self.subTest(confirm_reset=payload['confirm_reset'], action=payload['action']):
                    response = self.client.post(START, json=payload)
                    self.assertEqual(response.status_code, 400)
                    self.assertEqual(response.json()['detail']['error_code'], 'invalid_input')
                    self.assertEqual(response.headers.get('cache-control'), 'no-store')
                    self.assertNotIn(sentinel, response.text)
            start.assert_not_awaited()


class TotpResetApiTests(unittest.TestCase):
    """Reset-2FA over HTTP: real routes, real state machine and store, synthetic official service."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.services = []
        self.window = None             # official session the synthetic browser window ends up signed in to
        self.totp_accepted = False     # what the synthetic driver vouches for about its own TOTP submission
        self.stop = None               # the stop signal of the running task, once its window is open
        self.wait_for_stop = False     # the window gets signed in at the very moment a stop request arrives
        self.stop_afterwards = False   # the task is stopped right after the reset routine returned
        self.browser_calls = []
        driver = types.ModuleType(DRIVER_MODULE)
        driver.run_assisted_browser = self.synthetic_browser
        # No test of this class can launch Chrome, and no activation waits for a TOTP window.
        for active in (patch.dict(sys.modules, {DRIVER_MODULE: driver}),
                       patch('app.application.totp_reset.totp_seconds_left', return_value=20)):
            active.start()
            self.addCleanup(active.stop)
        context = make_client(Path(self.tmp.name))
        self.client = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        self.log = _LogCapture()
        logging.getLogger().addHandler(self.log)
        self.addCleanup(logging.getLogger().removeHandler, self.log)

    # ----- fixtures ---------------------------------------------------------------------------

    async def synthetic_browser(self, **kwargs):
        """Stands in for the visible Chrome window: it only "signs in" to ``self.window``."""
        self.browser_calls.append({'action': kwargs['action'], 'email': kwargs['email'],
                                   'totp_secret': kwargs['totp_secret']})
        self.stop = kwargs['cancel']
        on_mfa = kwargs.get('on_mfa')
        if on_mfa is None or self.window is None:
            return {'ok': False, 'state': 'manual_required', 'error_code': 'browser_closed',
                    'message': 'synthetic window closed'}
        while self.wait_for_stop and not self.stop.is_set():
            await asyncio.sleep(0.005)
        outcome = on_mfa(self.window, {'totp_accepted': self.totp_accepted})
        if inspect.isawaitable(outcome):
            outcome = await outcome
        if self.stop_afterwards:
            self.stop.set()
            return {'ok': False, 'state': 'cancelled', 'error_code': 'cancelled', 'message': 'synthetic stop'}
        if isinstance(outcome, dict) and outcome.get('ok') is True:
            return {'ok': True, 'state': 'success', 'message': 'synthetic routine finished'}
        return {'ok': False, 'state': 'manual_required', 'error_code': 'mfa_incomplete',
                'message': 'synthetic routine incomplete'}

    def login(self):
        self.assertEqual(self.client.post('/auth/login', json={'username': 'hixz12', 'password': 'test-password'}).status_code, 200)

    def on_app_loop(self, work):
        """Run ``work(session)`` on the app's own event loop, on a session of the app's own engine."""
        factory = self.client.app.state.session_factory

        async def call():
            async with factory() as db:
                return await work(db)
        return self.client.portal.call(call)

    def official(self, email=EMAIL, **options):
        service = OfficialService(email, **options)
        self.services.append(service)
        return service

    def reset(self, service, **options):
        """One run of the real state machine against the synthetic official service."""
        async def work(db):
            client = ChatGPTMfaClient(service, expected_email=service.email)
            return await totp_reset.run_reset(db, email=service.email, client=client,
                                              operation_id='seeded-run', **options)
        result = self.on_app_loop(work)
        self.assert_clean(json.dumps(result, ensure_ascii=False), codes=True)
        return result

    def seed(self, phase, email=EMAIL):
        """Leave a real record in ``phase`` by interrupting a real run at the matching official request."""
        service = self.official(email)
        service.plan.update({call: list(outcomes) for call, outcomes in INTERRUPTED_AT[phase].items()})
        result = self.reset(service)
        self.assertEqual(result['phase'], phase, result.get('error_code'))
        return service

    def status(self, email=EMAIL):
        response = self.client.post(STATUS, json={'email': email})
        self.assertEqual(response.status_code, 200, response.text)
        self.assert_private(response)
        self.assert_clean(response.text)
        return response.json()

    def start(self, **fields):
        return self.client.post(START, json={'email': EMAIL, 'password': PASSWORD, 'action': 'reset_totp', **fields})

    def begin(self, **fields):
        """Start a confirmed reset over HTTP; returns the id of its browser task."""
        response = self.start(confirm_reset=True, **fields)
        self.assertEqual(response.status_code, 202, response.text)
        self.assert_private(response)
        self.assert_clean(response.text)
        return response.json()['operation_id']

    def finish(self, operation_id):
        """Poll the task like the page does until it is over (normally a few milliseconds)."""
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            response = self.client.get('/api/assisted-login/' + operation_id)
            self.assertEqual(response.status_code, 200, response.text)
            self.assert_private(response)
            self.assert_clean(response.text)
            task = response.json()
            if task['state'] not in ('pending', 'queued', 'running', 'waiting'):
                self.assert_clean(json.dumps(task['result'], ensure_ascii=False), codes=True)
                return task
            time.sleep(0.01)
        self.fail('The synthetic browser task did not finish')

    def operation_rows(self):
        async def work(db):
            rows = await db.scalars(select(Operation).order_by(Operation.id))
            return [{'public_id': row.public_id, 'state': row.state, 'email': row.email,
                     'input_json': row.input_json, 'result_json': row.result_json,
                     'log_json': row.log_json, 'error_message': row.error_message} for row in rows]
        return self.on_app_loop(work)

    def add_operation(self, email, state):
        async def work(db):
            row = await operation_store.create(db, op_type='assisted_login', email=email, state=state,
                                               input_payload={'action': 'reset_totp'})
            await db.commit()
            return row.public_id
        return self.on_app_loop(work)

    def end_operation(self, public_id):
        async def work(db):
            row = await operation_store.get_by_public_id(db, public_id)
            await operation_store.finish(db, row, {'success': False, 'status': 'cancelled',
                                                   'error_code': 'cancelled', 'error': 'synthetic stop'})
            await db.commit()
        self.on_app_loop(work)

    def settings(self, prefix):
        async def work(db):
            rows = await db.scalars(select(SystemSetting))
            return {row.key: row.value for row in rows if row.key.startswith(prefix)}
        return self.on_app_loop(work)

    def put_setting(self, key, value):
        async def work(db):
            row = await db.get(SystemSetting, key)
            if row is None:
                db.add(SystemSetting(key=key, value=value))
            else:
                row.value = value
            await db.commit()
        self.on_app_loop(work)

    def add_owner(self, email, owner_key=''):
        """The email becomes a local account that owns one team (optionally with a stored owner 2FA)."""
        async def work(db):
            account = Account(email=email, local_purpose='standby', operational_state='available', auth_state='unknown')
            db.add(account)
            await db.flush()
            db.add(Workspace(name='Synthetic team', owner_account_id=account.id,
                             owner_totp_secret_encrypted=encrypt_secret(owner_key)))
            await db.commit()
        self.on_app_loop(work)

    def owner_keys(self, email):
        async def work(db):
            account = await db.scalar(select(Account).where(Account.email == email))
            rows = await db.scalars(select(Workspace).where(Workspace.owner_account_id == account.id))
            return [decrypt_secret(row.owner_totp_secret_encrypted) for row in rows]
        return self.on_app_loop(work)

    # ----- assertions -------------------------------------------------------------------------

    def assert_private(self, response):
        self.assertEqual(response.headers.get('cache-control'), 'no-store')

    def assert_error(self, response, status, code):
        self.assertEqual(response.status_code, status, response.text)
        self.assert_private(response)
        detail = response.json()['detail']
        self.assertEqual(detail['error_code'], code)
        self.assertTrue(isinstance(detail['message'], str) and detail['message'])
        self.assert_clean(response.text)

    def assert_clean(self, text, *, codes=False):
        """No key, password, token or official body text; ``codes`` adds every one-time code that was sent.

        Codes are six digits, so they are only looked for where no timestamp or hash can collide.
        """
        private = [NEW_SECRET, OLD_SECRET, MANUAL_SECRET, PASSWORD, REMOTE_NOTE]
        for service in self.services:
            private.append(service.token)
            if codes:
                private.extend(code for _, code in service.activations if isinstance(code, str) and code)
        for value in private:
            self.assertNotIn(value, text)

    def assert_nothing_at_rest(self):
        """Nothing private is readable in the SQLite files, in an operation row or in the process log."""
        stored = b''.join(path.read_bytes() for path in sorted(Path(self.tmp.name).iterdir()) if path.is_file())
        self.assertTrue(stored)
        for value in (NEW_SECRET, OLD_SECRET, MANUAL_SECRET, PASSWORD, REMOTE_NOTE, *(item.token for item in self.services)):
            self.assertFalse(value.encode() in stored, 'a private value is stored in plaintext')
        columns = '\n'.join(str(row[name]) for row in self.operation_rows()
                            for name in ('input_json', 'result_json', 'log_json', 'error_message'))
        self.assert_clean(columns, codes=True)
        self.assert_clean('\n'.join(self.log.lines))

    # ----- access control and input validation ------------------------------------------------

    def test_reset_endpoints_require_the_admin_session(self):
        self.seed('prepared')
        for path, payload in ((STATUS, {'email': EMAIL}), (REVEAL, {'email': EMAIL}),
                              (ABANDON, {'email': EMAIL, 'confirmed': True})):
            with self.subTest(path=path):
                response = self.client.post(path, json=payload)
                self.assertEqual(response.status_code, 401)
                self.assert_private(response)
                self.assert_clean(response.text)
        # The refused requests neither exported nor closed the record.
        self.login()
        state = self.status()
        self.assertEqual((state['phase'], state['open'], state['exported']), ('prepared', True, False))
        self.assertEqual(self.settings('totp_reset_archive:'), {})
        self.assert_nothing_at_rest()

    def test_reset_endpoints_refuse_cross_origin_and_malformed_requests(self):
        self.login()
        sentinel = 'SYNTHETIC-FIELD-NOT-FOR-ECHO'
        targets = ((STATUS, 'status_reset', {'email': EMAIL}, {'ok': True, 'phase': 'none'}),
                   (REVEAL, 'reveal_candidate', {'email': EMAIL}, {'email': EMAIL, 'secret': NEW_SECRET}),
                   (ABANDON, 'abandon_reset', {'email': EMAIL, 'confirmed': True}, {'ok': True, 'phase': 'abandoned'}))
        for path, name, payload, answer in targets:
            with self.subTest(path=path), patch('app.application.totp_reset.' + name, AsyncMock(return_value=answer)) as served:
                for headers in ({'origin': 'https://testserver'}, {'origin': 'http://other.example'},
                                {'sec-fetch-site': 'cross-site'}):
                    self.assert_error(self.client.post(path, json=payload, headers=headers), 403, 'origin_mismatch')
                # Only JSON is read: neither a form nor JSON text under another content type.
                self.assert_error(self.client.post(path, data={'email': EMAIL}), 415, 'json_required')
                self.assert_error(self.client.post(path, content=json.dumps(payload),
                                                   headers={'content-type': 'text/plain'}), 415, 'json_required')
                malformed = ('{', '[]', json.dumps({**payload, 'unexpected': sentinel}),
                             json.dumps({key: value for key, value in payload.items() if key != 'email'}),
                             json.dumps({**payload, 'email': 'not-an-email'}))
                for raw in malformed:
                    response = self.client.post(path, content=raw, headers={'content-type': 'application/json'})
                    self.assert_error(response, 400, 'invalid_input')
                    self.assertNotIn(sentinel, response.text)
                served.assert_not_awaited()
                # The same payload sent by the page itself is served, exactly once.
                response = self.client.post(path, json=payload, headers={'origin': 'http://testserver',
                                                                         'sec-fetch-site': 'same-origin'})
                self.assertEqual(response.status_code, 200)
                self.assert_private(response)
                served.assert_awaited_once()
                self.assertEqual(served.await_args.kwargs, payload)

    def test_start_without_confirmation_changes_nothing(self):
        self.login()
        self.window = self.official()
        for extra in ({}, {'confirm_reset': False}):
            with self.subTest(sent=extra):
                self.assert_error(self.start(totp_secret=OLD_SECRET, **extra), 400, 'reset_confirmation_required')
        self.assertEqual(self.browser_calls, [])
        self.assertEqual(self.window.calls, [])
        self.assertEqual(self.operation_rows(), [])
        self.assertEqual(self.status()['phase'], 'none')
        self.assert_nothing_at_rest()

    # ----- status ---------------------------------------------------------------------------

    def test_status_without_a_record_reports_none(self):
        self.login()
        state = self.status('nobody@example.com')
        self.assertEqual(state['phase'], 'none')
        self.assertIs(state['open'], False)
        self.assertFalse(state.get('has_candidate'))
        self.assertFalse(state.get('exported'))

    def test_status_of_every_phase_never_contains_the_key(self):
        self.login()
        expected = {'preparing': (True, False), 'prepared': (True, True), 'activating': (True, True),
                    'activated': (True, True), 'confirmed': (False, False)}
        for phase, (is_open, has_candidate) in expected.items():
            with self.subTest(phase=phase):
                email = phase + '@example.com'
                service = self.seed(phase, email)
                state = self.status(email)   # asserts no key, token or official text in the body
                self.assertEqual(state['phase'], phase)
                self.assertIs(state['open'], is_open)
                self.assertIs(state['has_candidate'], has_candidate)
                self.assertIs(state['exported'], False)
                self.assertTrue(isinstance(state['message'], str) and state['message'])
                # One-time codes: every field but the timestamps (their digits could collide by chance).
                fields = json.dumps({name: value for name, value in state.items() if not name.endswith('_at')})
                for _, code in service.activations:
                    self.assertNotIn(code, fields)
        # One record per email, whatever the spelling of the address.
        self.assertEqual(self.status('Prepared@Example.COM')['phase'], 'prepared')
        self.assert_nothing_at_rest()

    # ----- reveal ---------------------------------------------------------------------------

    def test_reveal_returns_the_candidate_as_attachment_and_records_the_export(self):
        self.login()
        for phase in ('prepared', 'activating', 'activated'):
            with self.subTest(phase=phase):
                email = phase + '@example.com'
                self.seed(phase, email)
                refused = self.client.get(REVEAL, params={'email': email})   # never served to a GET
                self.assertNotEqual(refused.status_code, 200)
                self.assert_clean(refused.text)
                self.assertIs(self.status(email)['exported'], False)
                response = self.client.post(REVEAL, json={'email': email})
                self.assertEqual(response.status_code, 200)
                self.assert_private(response)
                self.assertIn('attachment', response.headers['content-disposition'])
                self.assertEqual(response.json()['secret'], NEW_SECRET)
                self.assertEqual(response.json()['email'], email)
                state = self.status(email)
                self.assertIs(state['exported'], True)
                self.assertEqual((state['phase'], state['open'], state['has_candidate']), (phase, True, True))
        self.assert_nothing_at_rest()

    def test_reveal_without_a_candidate_is_not_found(self):
        self.login()
        self.assert_error(self.client.post(REVEAL, json={'email': 'nobody@example.com'}), 404, 'candidate_not_found')
        for phase in ('preparing', 'confirmed'):
            with self.subTest(phase=phase):
                email = phase + '@example.com'
                self.seed(phase, email)
                self.assert_error(self.client.post(REVEAL, json={'email': email}), 404, 'candidate_not_found')
                self.assertIs(self.status(email)['exported'], False)
        self.assert_nothing_at_rest()

    # ----- abandon --------------------------------------------------------------------------

    def test_abandon_needs_confirmation_and_export_then_archives_the_record(self):
        self.login()
        self.assert_error(self.client.post(ABANDON, json={'email': 'nobody@example.com', 'confirmed': True}),
                          409, 'reset_not_open')
        self.seed('activating')
        for payload in ({'email': EMAIL, 'confirmed': False}, {'email': EMAIL}):
            self.assert_error(self.client.post(ABANDON, json=payload), 400, 'confirmation_required')
        for truthy in ('yes', 'true', 1):   # only the boolean is a confirmation
            response = self.client.post(ABANDON, json={'email': EMAIL, 'confirmed': truthy})
            self.assertEqual(response.status_code, 400)
            self.assert_private(response)
        # The outcome of the activation is unknown: the key may be live, so it must be exported first.
        self.assert_error(self.client.post(ABANDON, json={'email': EMAIL, 'confirmed': True}), 409, 'export_required')
        state = self.status()
        self.assertEqual((state['phase'], state['open'], state['has_candidate']), ('activating', True, True))
        self.assertEqual(self.settings('totp_reset_archive:'), {})

        self.assertEqual(self.client.post(REVEAL, json={'email': EMAIL}).json()['secret'], NEW_SECRET)
        response = self.client.post(ABANDON, json={'email': EMAIL, 'confirmed': True})
        self.assertEqual(response.status_code, 200, response.text)
        self.assert_private(response)
        self.assert_clean(response.text)
        closed = response.json()
        self.assertEqual((closed['phase'], closed['open'], closed['has_candidate']), ('abandoned', False, False))

        self.assert_error(self.client.post(ABANDON, json={'email': EMAIL, 'confirmed': True}), 409, 'reset_not_open')
        self.assert_error(self.client.post(REVEAL, json={'email': EMAIL}), 404, 'candidate_not_found')
        state = self.status()
        self.assertEqual((state['phase'], state['open'], state['has_candidate']), ('abandoned', False, False))
        # The record that held the key is archived, still encrypted and still complete.
        archive = self.settings('totp_reset_archive:')
        self.assertEqual(len(archive), 1)
        (kept,) = archive.values()
        self.assertNotIn(NEW_SECRET, kept)
        self.assertIn(NEW_SECRET, token_cipher().decrypt(kept))
        self.assert_nothing_at_rest()

    def test_abandon_is_refused_while_a_browser_task_is_active(self):
        self.login()
        self.seed('prepared')
        self.add_operation('someone-else@example.com', 'running')   # another email's task is not in the way
        for state in ('pending', 'queued', 'running', 'waiting'):
            with self.subTest(state=state):
                public_id = self.add_operation(EMAIL, state)
                self.assert_error(self.client.post(ABANDON, json={'email': EMAIL, 'confirmed': True}), 409, 'account_busy')
                self.assertEqual(self.status()['phase'], 'prepared')
                self.end_operation(public_id)
        response = self.client.post(ABANDON, json={'email': EMAIL, 'confirmed': True})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['phase'], 'abandoned')
        self.assertEqual(len(self.settings('totp_reset_archive:')), 1)
        self.assert_nothing_at_rest()

    # ----- manual backup next to a reset ----------------------------------------------------------

    def test_manual_backup_is_refused_while_a_reset_is_open(self):
        self.login()
        for phase in ('preparing', 'prepared', 'activating', 'activated'):
            with self.subTest(phase=phase):
                email = phase + '@example.com'
                self.seed(phase, email)
                response = self.client.post(BACKUP, json={'email': email, 'secret': MANUAL_SECRET, 'confirmed': True})
                self.assert_error(response, 409, 'reset_pending')
                kept = self.client.post(BACKUP_REVEAL, json={'email': email})
                if phase == 'activated':
                    # The acknowledged key already is the backup, and the manual copy did not replace it.
                    self.assertEqual(kept.status_code, 200)
                    self.assertEqual((kept.json()['secret'], kept.json()['verification']), (NEW_SECRET, 'official_activated'))
                else:
                    self.assertEqual(kept.status_code, 404)   # neither the manual key nor an unconfirmed candidate
        # Another email is not held back by those records.
        response = self.client.post(BACKUP, json={'email': 'someone-else@example.com', 'secret': MANUAL_SECRET, 'confirmed': True})
        self.assertEqual(response.status_code, 200, response.text)
        self.assert_nothing_at_rest()

    def test_manual_backup_works_again_once_the_reset_is_closed(self):
        self.login()
        abandoned, confirmed = 'abandoned@example.com', 'confirmed@example.com'
        self.seed('prepared', abandoned)
        service = self.seed('activated', confirmed)
        for email in (abandoned, confirmed):
            response = self.client.post(BACKUP, json={'email': email, 'secret': MANUAL_SECRET, 'confirmed': True})
            self.assert_error(response, 409, 'reset_pending')
        # One record is closed by the user, the other by completing the official confirmation,
        # which only reads the status of the already acknowledged key.
        self.assertEqual(self.client.post(ABANDON, json={'email': abandoned, 'confirmed': True}).status_code, 200)
        sent = len(service.calls)
        self.assertEqual(self.reset(service)['phase'], 'confirmed')
        self.assertEqual(service.calls[sent:], [SESSION, INFO])
        for email in (abandoned, confirmed):
            with self.subTest(email=email):
                response = self.client.post(BACKUP, json={'email': email, 'secret': MANUAL_SECRET, 'confirmed': True})
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.json()['verification'], 'user_reported')
                self.assert_clean(response.text)
                shown = self.client.post(BACKUP_REVEAL, json={'email': email}).json()
                self.assertEqual((shown['secret'], shown['verification']), (MANUAL_SECRET, 'user_reported'))
        self.assert_nothing_at_rest()

    def test_backup_reveal_reports_official_confirmation_after_a_completed_reset(self):
        self.login()
        saved = self.client.post(BACKUP, json={'email': EMAIL, 'secret': OLD_SECRET, 'confirmed': True})
        self.assertEqual((saved.status_code, saved.json()['verification']), (200, 'user_reported'))
        result = self.reset(self.official())
        self.assertEqual((result['ok'], result['status'], result['phase']), (True, 'success', 'confirmed'))
        self.assertIs(result['backup_saved'], True)
        response = self.client.post(BACKUP_REVEAL, json={'email': EMAIL})
        self.assertEqual(response.status_code, 200)
        self.assert_private(response)
        self.assertIn('attachment', response.headers['content-disposition'])
        self.assertEqual(response.json()['secret'], NEW_SECRET)
        self.assertEqual(response.json()['verification'], 'official_confirmed')
        # The confirmed record keeps no key: nothing is left to export or to abandon.
        self.assert_error(self.client.post(REVEAL, json={'email': EMAIL}), 404, 'candidate_not_found')
        self.assert_error(self.client.post(ABANDON, json={'email': EMAIL, 'confirmed': True}), 409, 'reset_not_open')
        (record,) = self.settings('totp_reset:').values()
        self.assertNotIn(NEW_SECRET, token_cipher().decrypt(record))
        self.assert_nothing_at_rest()

    # ----- unreadable record ------------------------------------------------------------------

    def test_unreadable_record_is_reported_and_left_untouched(self):
        self.login()
        key = 'totp_reset:' + hashlib.sha256(EMAIL.encode()).hexdigest()
        # A record written under another encryption key may hold the only copy of a live key.
        foreign = TokenCipher('another-installation-key').encrypt(json.dumps({
            'schema': 1, 'email': EMAIL, 'phase': 'activating', 'secret': NEW_SECRET, 'session_id': 'enrol-session-1'}))
        for value in ('not-a-ciphertext', foreign):
            with self.subTest(value=value[:16]):
                self.put_setting(key, value)
                self.assert_error(self.client.post(STATUS, json={'email': EMAIL}), 409, 'reset_unreadable')
                for response in (self.client.post(REVEAL, json={'email': EMAIL}),
                                 self.client.post(ABANDON, json={'email': EMAIL, 'confirmed': True})):
                    self.assertGreaterEqual(response.status_code, 400)
                    self.assert_private(response)
                    self.assert_clean(response.text)
                self.assertEqual(self.settings('totp_reset'), {key: value})   # same row, no archive beside it
        # A new reset is refused before any browser or operation exists ...
        self.window = self.official()
        self.assert_error(self.start(confirm_reset=True), 409, 'reset_unreadable')
        self.assertEqual((self.browser_calls, self.window.calls, self.operation_rows()), ([], [], []))
        # ... while the other actions are still served.
        response = self.client.post(START, json={'email': EMAIL, 'password': PASSWORD, 'action': 'security'})
        self.assertEqual(response.status_code, 202, response.text)
        self.finish(response.json()['operation_id'])
        self.assertEqual([call['action'] for call in self.browser_calls], ['security'])
        self.assertEqual(self.window.calls, [])
        self.assertEqual(self.settings('totp_reset'), {key: foreign})
        self.assert_nothing_at_rest()

    # ----- page -------------------------------------------------------------------------------

    def test_accounts_page_and_script_offer_the_reset(self):
        self.login()
        page = self.client.get('/accounts', headers={'accept': 'text/html'})
        self.assertEqual(page.status_code, 200)
        for marker in ('id="assisted-login-sheet"', 'id="assisted-login-body"', 'id="assisted-login-open"'):
            self.assertIn(marker, page.text)
        tag = re.search(r'<script src="(/static/js/assisted-login\.js[^"]*)"', page.text)
        self.assertIsNotNone(tag)
        for url in (tag.group(1), '/static/js/assisted-login.js'):
            script = self.client.get(url)
            self.assertEqual(script.status_code, 200, url)
            for needle in ('reset_totp', 'confirm_reset', STATUS, REVEAL, ABANDON):
                self.assertIn(needle, script.text)

    # ----- the browser task, end to end -------------------------------------------------------------

    def test_task_status_exposes_only_whitelisted_result_fields(self):
        self.login()
        planted = 'SYNTHETIC-FIELD-NOT-FOR-STATUS'

        async def work(db):
            row = await operation_store.create(db, op_type='assisted_login', email=EMAIL,
                                               input_payload={'action': 'reset_totp', 'mode': 'resume'})
            await operation_store.finish(db, row, {
                'ok': False, 'success': False, 'status': 'manual_required', 'error_code': 'confirm_pending',
                'message': 'synthetic outcome', 'error': 'synthetic outcome', 'phase': 'activated', 'backup_saved': True,
                'secret': planted, 'totp_secret': planted, 'session_id': planted, 'access_token': planted,
                'debug': {'body': planted}})
            await db.commit()
            return row.public_id
        response = self.client.get('/api/assisted-login/' + self.on_app_loop(work))
        self.assertEqual(response.status_code, 200)
        self.assert_private(response)
        task = response.json()
        self.assertEqual((task['state'], task['action'], task['mode']), ('manual_required', 'reset_totp', 'resume'))
        result = task['result']
        self.assertEqual((result['error_code'], result['phase'], result['backup_saved']), ('confirm_pending', 'activated', True))
        self.assertNotIn(planted, response.text)

    def test_confirmed_start_replaces_the_key_end_to_end(self):
        self.login()
        self.add_owner(EMAIL)
        saved = self.client.post(BACKUP, json={'email': EMAIL, 'secret': OLD_SECRET, 'confirmed': True})
        self.assertEqual(saved.status_code, 200)
        service = self.window = self.official()
        self.stop_afterwards = True   # whatever happens to the window afterwards, the reset's own outcome is the truth
        task = self.finish(self.begin())   # 2FA field left blank: the key saved for the email signs in

        self.assertEqual((task['state'], task['action'], task['mode']), ('success', 'reset_totp', 'fresh'))
        result = task['result']
        self.assertEqual((result['ok'], result['success'], result['status'], result['phase']),
                         (True, True, 'success', 'confirmed'))
        self.assertIs(result['backup_saved'], True)
        self.assertEqual(result['owner_synced'], 1)
        self.assertEqual(self.browser_calls, [{'action': 'reset_totp', 'email': EMAIL, 'totp_secret': OLD_SECRET}])
        # Read first, then disable -> enrol -> activate, then read again; one code from the new key.
        self.assertEqual(service.calls, [SESSION, INFO, DISABLE, ENROLL, ACTIVATE, INFO])
        self.assertEqual(service.factors, ['factor-new-1'])
        self.assertEqual(len(service.activations), 1)

        state = self.status()
        self.assertEqual((state['phase'], state['open'], state['has_candidate']), ('confirmed', False, False))
        shown = self.client.post(BACKUP_REVEAL, json={'email': EMAIL}).json()
        self.assertEqual((shown['secret'], shown['verification']), (NEW_SECRET, 'official_confirmed'))
        self.assertEqual(self.owner_keys(EMAIL), [NEW_SECRET])
        (row,) = self.operation_rows()
        self.assertEqual((row['state'], row['email']), ('success', EMAIL))
        self.assert_nothing_at_rest()

    def test_blank_2fa_field_signs_in_with_the_key_kept_on_this_machine(self):
        self.login()

        def sign_in_key(**fields):
            """The key the browser window is handed for a login whose form sent ``fields``."""
            response = self.client.post(START, json={'email': EMAIL, 'password': PASSWORD, 'action': 'security', **fields})
            self.assertEqual(response.status_code, 202, response.text)
            self.assert_clean(response.text)
            self.finish(response.json()['operation_id'])
            return self.browser_calls[-1]['totp_secret']

        self.assertEqual(sign_in_key(), '')                    # nothing is kept for the email yet
        self.add_owner(EMAIL, owner_key=OLD_SECRET)
        self.assertEqual(sign_in_key(), OLD_SECRET)            # the stored owner 2FA of the email's team
        saved = self.client.post(BACKUP, json={'email': EMAIL, 'secret': MANUAL_SECRET, 'confirmed': True})
        self.assertEqual(saved.status_code, 200, saved.text)
        self.assertEqual(sign_in_key(), MANUAL_SECRET)         # the email's saved backup comes before it
        self.seed('activating')
        self.assertEqual(sign_in_key(), NEW_SECRET)            # a candidate that may already be live comes first
        self.assertEqual(sign_in_key(totp_secret=OLD_SECRET), OLD_SECRET)   # a typed key is used as typed
        self.assertEqual(len(self.browser_calls), 5)
        self.assert_nothing_at_rest()

    def test_stop_before_the_first_change_sends_nothing(self):
        self.login()
        service = self.window = self.official()
        self.wait_for_stop = True
        operation_id = self.begin(totp_secret=OLD_SECRET)
        response = self.client.post('/api/assisted-login/' + operation_id + '/cancel')
        self.assertEqual(response.status_code, 200, response.text)
        task = self.finish(operation_id)
        self.assertEqual((task['state'], task['result']['error_code']), ('cancelled', 'cancelled'))
        # Reading is all that happened: the old factor is still the only one and no record was opened.
        self.assertEqual([call for call in service.calls if call[0] != 'GET'], [])
        self.assertEqual(service.factors, ['factor-old'])
        self.assertEqual(self.status()['phase'], 'none')
        self.assert_nothing_at_rest()

    def test_stop_after_the_first_change_does_not_cut_the_reset_short(self):
        self.login()
        service = self.window = self.official()
        service.on_call[DISABLE] = lambda: self.stop.set()   # the stop arrives while the old factor is being disabled
        task = self.finish(self.begin(totp_secret=OLD_SECRET))
        self.assertTrue(self.stop.is_set())
        # A half-done reset would leave the account without 2FA: the run goes on to the confirmed key.
        self.assertEqual(service.calls, [SESSION, INFO, DISABLE, ENROLL, ACTIVATE, INFO])
        self.assertEqual((task['state'], task['result']['phase']), ('success', 'confirmed'))
        shown = self.client.post(BACKUP_REVEAL, json={'email': EMAIL}).json()
        self.assertEqual((shown['secret'], shown['verification']), (NEW_SECRET, 'official_confirmed'))
        self.assert_nothing_at_rest()

    def test_remote_refresh_ownership_blocks_other_actions_but_not_the_reset(self):
        self.login()
        self.add_owner(EMAIL)
        service = self.window = self.official()
        with patch('app.application.assisted_login.refresh_owner_kind', AsyncMock(return_value='sub2api')):
            for action in ('oauth', 'security', 'logout_all'):
                with self.subTest(action=action):
                    response = self.client.post(START, json={'email': EMAIL, 'password': PASSWORD, 'action': action})
                    self.assert_error(response, 409, 'remote_refresh_owned')
            self.assertEqual((self.browser_calls, service.calls, self.operation_rows()), ([], [], []))
            # A reset neither reads nor replaces the stored authorization, so it is not held back.
            task = self.finish(self.begin(totp_secret=OLD_SECRET))
        self.assertEqual((task['state'], task['mode'], task['result']['phase']), ('success', 'fresh', 'confirmed'))
        self.assertEqual(service.factors, ['factor-new-1'])
        self.assert_nothing_at_rest()

    def test_refused_activation_is_resumed_with_the_stored_enrolment(self):
        self.login()
        service = self.window = self.official()
        service.plan[ACTIVATE] = [REFUSAL]
        first = self.finish(self.begin(totp_secret=OLD_SECRET))
        self.assertEqual((first['state'], first['mode']), ('manual_required', 'fresh'))
        result = first['result']
        self.assertEqual((result['success'], result['error_code'], result['phase']), (False, 'activation_rejected', 'prepared'))
        # Only the status and the sanitized code of the official answer are kept, never its text.
        self.assertEqual((result['remote_status'], result['remote_code']), (400, 'invalid_code'))
        state = self.status()
        self.assertEqual((state['phase'], state['open'], state['has_candidate']), ('prepared', True, True))

        sent = len(service.calls)
        second = self.finish(self.begin())
        self.assertEqual((second['state'], second['mode']), ('success', 'resume'))
        self.assertEqual((second['result']['phase'], second['result']['backup_saved']), ('confirmed', True))
        # The record is continued: status first, then the same enrolment again, never a second key.
        self.assertEqual(service.calls[sent:], [SESSION, INFO, ACTIVATE, INFO])
        self.assertEqual(service.enrolled, 1)
        self.assertEqual([session for session, _ in service.activations], ['enrol-session-1', 'enrol-session-1'])
        # A key that is stored but not live never signs in.
        self.assertEqual([call['totp_secret'] for call in self.browser_calls], [OLD_SECRET, ''])
        shown = self.client.post(BACKUP_REVEAL, json={'email': EMAIL}).json()
        self.assertEqual((shown['secret'], shown['verification']), (NEW_SECRET, 'official_confirmed'))
        self.assertEqual([row['state'] for row in self.operation_rows()], ['manual_required', 'success'])
        self.assert_nothing_at_rest()

    def test_unknown_activation_is_settled_with_the_candidate_key_without_a_second_enrolment(self):
        self.login()
        service = self.official(names_factor=False)   # enrol gives no factor id to recognise the key by
        service.plan.update({ACTIVATE: [LOST_AFTER], INFO: [None, LOST]})
        seeded = self.reset(service)                  # the key went live, but neither answer arrived
        self.assertEqual((seeded['error_code'], seeded['phase']), ('activation_unconfirmed', 'activating'))
        self.window, sent = service, len(service.calls)

        # The window is signed in, but the driver cannot vouch for a code typed from the stored key.
        first = self.finish(self.begin(totp_secret=OLD_SECRET))
        self.assertEqual(first['mode'], 'resume')
        self.assertEqual((first['result']['success'], first['result']['error_code'], first['result']['phase']),
                         (False, 'factor_unmatched', 'activating'))
        self.assertEqual(self.status()['phase'], 'activating')

        # Signing in with a code generated from the stored key proves that it is the live factor.
        self.totp_accepted = True
        second = self.finish(self.begin(totp_secret=OLD_SECRET))
        self.assertEqual((second['state'], second['mode'], second['result']['phase']), ('success', 'resume', 'confirmed'))

        # Whatever was typed, only the candidate can pass a 2FA prompt once an activation may have landed.
        self.assertEqual([call['totp_secret'] for call in self.browser_calls], [NEW_SECRET, NEW_SECRET])
        # Both runs only read; no second key, no second activation.
        self.assertEqual(service.calls[sent:], [SESSION, INFO, SESSION, INFO])
        self.assertEqual((service.enrolled, len(service.activations)), (1, 1))
        state = self.status()
        self.assertEqual((state['phase'], state['open'], state['has_candidate']), ('confirmed', False, False))
        shown = self.client.post(BACKUP_REVEAL, json={'email': EMAIL}).json()
        self.assertEqual((shown['secret'], shown['verification']), (NEW_SECRET, 'official_confirmed'))
        self.assert_nothing_at_rest()
