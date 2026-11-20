"""Durable 2FA reset state machine and encrypted key stores, fully offline.

Every scenario drives the real ChatGPTMfaClient over an in-memory model of one
account's MFA endpoints, on a temporary SQLite file. No browser, no network and
no real account: every key, code and token here is synthetic.
"""
import asyncio
import base64
import contextlib
import hashlib
import json
import logging
import secrets
import tempfile
import time
import unittest
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import create_async_engine

import app.main  # noqa: F401 - registers every model before create_all
from app.application import assisted_login, totp_backup, totp_reset
from app.application.operations import operation_store
from app.application.tokens import decrypt_secret, encrypt_secret
from app.core.crypto import token_cipher
from app.integrations.auth_bridge.credentials import CredentialImportError
from app.integrations.openai.mfa import ChatGPTMfaClient, MfaTransportError, generate_totp
from app.persistence.database import Base, create_session_factory
from app.persistence.models.identity import Account, Workspace
from app.persistence.models.operations import Operation
from app.persistence.models.settings import SystemSetting

EMAIL = 'owner@example.com'
OTHER_EMAIL = 'other@example.com'
OLD_SECRET = 'JBSWY3DPEHPK3PXP'                      # the key in use before a reset
NEW_SECRET = 'KRSXG5DSNFXGOIDBKRSXG5DSNFXGOIDB'      # first key the fake server issues
SECOND_SECRET = 'MFRGGZDFMZTWQ2LKMFRGGZDFMZTWQ2LK'   # second enrolment
THIRD_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'    # third enrolment
FOREIGN_SECRET = 'ORSXG5DTMVRXEZLUORSXG5DTMVRXEZLU'  # owner 2FA of somebody else's team
MANUAL_SECRET = 'ON4W45DIMV2GSYZNN53W4ZLSFVVWK6JB'   # a key the user types into the manual backup
KEYS = (OLD_SECRET, NEW_SECRET, SECOND_SECRET, THIRD_SECRET, FOREIGN_SECRET, MANUAL_SECRET)

# The documented remote protocol.
SESSION = '/api/auth/session'
INFO = '/backend-api/accounts/mfa_info'
DISABLE = '/backend-api/accounts/mfa/user/disable_in_house'
ENROLL = '/backend-api/accounts/mfa/enroll'
ACTIVATE = '/backend-api/accounts/mfa/user/activate_enrollment'
ROUTES = {('GET', SESSION): 'session', ('GET', INFO): 'info', ('POST', DISABLE): 'disable',
          ('POST', ENROLL): 'enroll', ('POST', ACTIVATE): 'activate'}
MUTATING = ('disable', 'enroll', 'activate')
FULL = ['session', 'info', 'disable', 'enroll', 'activate', 'info']  # a fresh run over an old factor
BARE = ['session', 'info', 'enroll', 'activate', 'info']             # a fresh run without 2FA
OPEN = ('preparing', 'prepared', 'activating', 'activated')
KEYED = ('prepared', 'activating', 'activated')
NO_2FA = {'mfa_enabled': False, 'mfa_enabled_v2': False, 'factors': {'totp': []}, 'native_default_factor_id': None}
OUTAGE = {'detail': 'synthetic outage'}
BAD_CODE = {'error': {'code': 'invalid_code'}}
_SAME = object()


def reset_key(email):
    return 'totp_reset:' + hashlib.sha256(email.encode()).hexdigest()


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def access_token(email=EMAIL, *, profile=_SAME, **claims):
    """Unsigned synthetic JWT; the application decodes it without verifying."""
    payload = {'exp': int(time.time()) + 3600, **claims}
    if email:
        payload['email'] = email
    profile = email if profile is _SAME else profile
    if profile:
        payload['https://api.openai.com/profile'] = {'email': profile}
    parts = ({'alg': 'RS256', 'typ': 'JWT'}, payload)
    return '.'.join([*(_b64(json.dumps(part).encode()) for part in parts), _b64(b'synthetic-signature')])


def reply(status, body=None):
    """Answer with this status and body; the request is NOT applied."""
    return ('reply', status, body)


def dropped():
    """The request never reaches the server: nothing applied, no response."""
    return ('dropped',)


def lost(status=None):
    """The server applies the request, then the response is lost (None) or replaced by a 5xx."""
    return ('lost', status)


def stalled():
    """The server applies the request and the response never comes (until the task is torn down)."""
    return ('stalled',)


@dataclass
class Call:
    endpoint: str
    number: int      # 1-based count of requests to this endpoint on this server
    method: str
    path: str
    headers: dict
    body: object
    data: object     # decoded JSON body, if any
    at: float
    durable: object  # committed local state when the request arrived (second session)


@dataclass
class Durable:
    record: object   # decrypted reset record, None, or the error raised while reading it
    backup: object   # (key, verification) of the email's backup, or None
    owners: dict     # workspace id -> decrypted stored owner 2FA ('' when empty)


class FakeMfaServer:
    """One account's MFA endpoints behind the page transport.

    The account outlives a browser task, so a test keeps one instance across
    runs. ``plan(endpoint, number, behaviour)`` scripts the number-th request to
    an endpoint, counted over the lifetime of the instance.
    """

    def __init__(self, *, email=EMAIL, factors=(), probe=None, keys=(NEW_SECRET, SECOND_SECRET, THIRD_SECRET)):
        self.tokens = set()
        self.factors = list(factors)   # ids of active TOTP factors, in listing order
        self.enrolments = []           # every enrolment issued: secret, session_id, factor_id
        self.pending = {}              # enrolment session id -> enrolment awaiting activation
        self.calls = []
        self.return_factor_id = True   # False: the enrol answer names no factor
        self.listed_as = None          # id an activated factor is listed under (default: its own)
        self.stalled = asyncio.Event()
        self._keys, self._plan, self._probe = list(keys), {}, probe
        self.sign_in({'user': {'id': 'user-fixture', 'email': email}, 'expires': '2099-01-01T00:00:00.000Z',
                      'accessToken': access_token(email)})

    def sign_in(self, payload):
        """Replace what the page's own session endpoint answers."""
        self.session = payload
        self.token = payload.get('accessToken') or ''
        if self.token:
            self.tokens.add(self.token)

    def plan(self, endpoint, number, behaviour):
        self._plan[(endpoint, number)] = behaviour

    def count(self, endpoint):
        return sum(1 for call in self.calls if call.endpoint == endpoint)

    def upcoming(self, endpoint):
        return self.count(endpoint) + 1

    def of(self, endpoint):
        return [call for call in self.calls if call.endpoint == endpoint]

    def names(self, start=0):
        return [call.endpoint for call in self.calls[start:]]

    def enrolment(self, session_id):
        return next((item for item in self.enrolments if item['session_id'] == session_id), None)

    def mfa_info(self):
        return {'mfa_enabled': bool(self.factors), 'mfa_enabled_v2': bool(self.factors),
                'factors': {'totp': [{'id': item, 'factor_type': 'totp'} for item in self.factors], 'sms': []},
                'native_default_factor_id': self.factors[0] if self.factors else None}

    async def request(self, method, path, *, headers, body):
        endpoint = ROUTES.get((method, path), 'unknown')
        try:
            data = json.loads(body) if isinstance(body, str) else None
        except ValueError:
            data = None
        call = Call(endpoint, self.count(endpoint) + 1, method, path,
                    {str(name).lower(): value for name, value in dict(headers or {}).items()}, body, data,
                    time.time(), await self._probe() if self._probe else None)
        self.calls.append(call)
        behaviour = self._plan.pop((endpoint, call.number), ('serve',))
        if behaviour[0] == 'dropped':
            raise MfaTransportError()
        if behaviour[0] == 'reply':
            content = behaviour[2]
            return behaviour[1], content if content is None or isinstance(content, str) else json.dumps(content)
        status, payload = self._serve(call)
        if behaviour[0] == 'lost':
            if behaviour[1] is None:
                raise MfaTransportError()
            return behaviour[1], json.dumps(OUTAGE)
        if behaviour[0] == 'stalled':
            self.stalled.set()
            await asyncio.Event().wait()
        return status, json.dumps(payload)

    def _serve(self, call):
        if call.endpoint == 'session':
            return 200, self.session
        if call.endpoint == 'unknown':
            return 404, {'error': {'code': 'not_found'}}
        if not self.token or call.headers.get('authorization') != 'Bearer ' + self.token:
            return 401, {'error': {'code': 'token_invalid'}}
        data = call.data if isinstance(call.data, dict) else {}
        if call.endpoint == 'info':
            return 200, self.mfa_info()
        if call.endpoint == 'disable':
            if data.get('factor_id') not in self.factors:
                return 404, {'error': {'code': 'factor_not_found'}}
            self.factors.remove(data['factor_id'])
            return 200, {'success': True}
        if call.endpoint == 'enroll':
            if data != {'factor_type': 'totp'}:
                return 400, {'error': {'code': 'invalid_request'}}
            index = len(self.enrolments) + 1
            issued = {'secret': self._keys[index - 1], 'session_id': f'enrol-session-{index}',
                      'factor_id': f'factor-new-{index}'}
            self.enrolments.append(issued)
            self.pending[issued['session_id']] = issued
            answer = {'secret': issued['secret'], 'session_id': issued['session_id']}
            if self.return_factor_id:
                answer['factor'] = {'id': issued['factor_id'], 'factor_type': 'totp'}
            return 200, answer
        issued = self.pending.get(data.get('session_id'))
        if issued is None or data.get('factor_type') != 'totp':
            return 400, {'error': {'code': 'enrollment_not_found'}}
        # Like the real service, accept the code of the current window or the one just before it.
        if data.get('code') not in {generate_totp(issued['secret'], timestamp=call.at),
                                    generate_totp(issued['secret'], timestamp=max(0.0, call.at - 30))}:
            return 400, BAD_CODE
        del self.pending[issued['session_id']]
        self.factors.append(self.listed_as or issued['factor_id'])
        return 200, {'success': True}


class _Capture(logging.Handler):
    def __init__(self, sink):
        super().__init__(logging.DEBUG)
        self.sink = sink

    def emit(self, record):
        try:
            text = record.getMessage()
        except Exception:
            text = str(record.msg) + repr(record.args)
        if record.exc_info:
            text += '\n' + logging.Formatter().formatException(record.exc_info)
        self.sink.append(text)


class ResetCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.engine = create_async_engine('sqlite+aiosqlite:///' + str(Path(self.tmp.name) / 'fixture.db'))
        self.addAsyncCleanup(self.engine.dispose)
        async with self.engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        # Same session options as the running service.
        self.factory = create_session_factory(self.engine)
        self.servers, self.trace, self.sleeps, self.logged = [], [], [], []
        self.server = self.new_server()
        real_sleep = asyncio.sleep

        async def fast_sleep(delay, result=None):
            self.sleeps.append(delay)
            return await real_sleep(0, result)

        # Never wait for a TOTP window or a retry pause.
        for patcher in (patch.object(totp_reset, 'totp_seconds_left', return_value=20),
                        patch('asyncio.sleep', fast_sleep)):
            patcher.start()
            self.addCleanup(patcher.stop)
        logger, capture = logging.getLogger('app'), _Capture(self.logged)
        level, propagate = logger.level, logger.propagate
        logger.addHandler(capture)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False

        def restore():
            logger.removeHandler(capture)
            logger.setLevel(level)
            logger.propagate = propagate

        self.addCleanup(restore)

    # ---- fixtures -------------------------------------------------------

    def new_server(self, **options):
        options.setdefault('probe', self.durable)
        server = FakeMfaServer(**options)
        self.servers.append(server)
        return server

    async def restart(self, **options):
        """Empty tables and a new account model: one more variant inside a test."""
        async with self.factory() as db:
            for model in (Operation, Workspace, SystemSetting, Account):
                await db.execute(delete(model))
            await db.commit()
        self.server = self.new_server(**options)
        return self.server

    async def seed_owner(self, email=EMAIL, keys=(OLD_SECRET, None)):
        """An Account and the teams it owns; returns the workspace ids."""
        async with self.factory() as db:
            account = Account(email=email, local_purpose='mother', operational_state='available', auth_state='unknown')
            db.add(account)
            await db.flush()
            rows = [Workspace(name=f'Fixture {index}', status='active', owner_account_id=account.id,
                              owner_totp_secret_encrypted=encrypt_secret(key)) for index, key in enumerate(keys)]
            db.add_all(rows)
            await db.commit()
            return [row.id for row in rows]

    async def add_operation(self, state, *, email=EMAIL, op_type='assisted_login'):
        async with self.factory() as db:
            row = Operation(public_id='op-' + secrets.token_hex(4), op_type=op_type, state=state, email=email)
            db.add(row)
            await db.commit()
            return row.id

    async def set_operation(self, row_id, state):
        async with self.factory() as db:
            (await db.get(Operation, row_id)).state = state
            await db.commit()

    async def settings(self, prefix):
        async with self.factory() as db:
            return {row.key: row.value for row in await db.scalars(select(SystemSetting)) if row.key.startswith(prefix)}

    async def rewrite(self, prefix, change):
        """Tamper with the single stored value under a key prefix."""
        async with self.factory() as db:
            rows = [row for row in await db.scalars(select(SystemSetting)) if row.key.startswith(prefix)]
            self.assertEqual(len(rows), 1)
            rows[0].value = change(rows[0].value)
            await db.commit()

    async def archives(self):
        """Decrypted archive rows of abandoned records."""
        cipher = token_cipher()
        return [json.loads(cipher.decrypt(value)) for value in (await self.settings('totp_reset_archive:')).values()]

    # ---- observation ----------------------------------------------------

    async def durable(self, email=EMAIL):
        """Committed state as a second session of the same engine sees it right now."""
        async with self.factory() as other:
            try:
                record = await totp_reset.load(other, email)
            except CredentialImportError as exc:
                record = exc
            try:
                found = await totp_backup.reveal_backup(other, email=email)
                backup = (found['secret'], found['verification'])
            except CredentialImportError as exc:
                backup = None if exc.code == 'backup_not_found' else exc
            owners = {row.id: decrypt_secret(row.owner_totp_secret_encrypted)
                      for row in await other.scalars(select(Workspace).order_by(Workspace.id))}
        return Durable(record, backup, owners)

    async def call(self, function, *args, **kwargs):
        """One request-scoped session per call, as the HTTP layer provides."""
        async with self.factory() as db:
            return await function(db, *args, **kwargs)

    async def refused(self, function, *args, **kwargs):
        """(code, status) of the error a store call is refused with; its text holds no secret."""
        with self.assertRaises(CredentialImportError) as caught:
            await self.call(function, *args, **kwargs)
        error = caught.exception
        self.assert_public(' | '.join((str(error), repr(error), str(error.code), str(error.message))), what='error')
        return error.code, error.status_code

    async def view(self, email=EMAIL):
        view = await self.call(totp_reset.status_reset, email=email)
        self.assert_public(view, what='status view')
        return view

    def private_values(self):
        return set(KEYS).union(*(server.tokens for server in self.servers))

    def sent_codes(self):
        return {call.data['code'] for server in self.servers for call in server.of('activate')
                if isinstance(call.data, dict) and isinstance(call.data.get('code'), str) and call.data['code']}

    def assert_public(self, value, *, what='result'):
        """No key, access token or submitted code in a result, view, row, log line or message."""
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
        for private in sorted(self.private_values()):
            self.assertNotIn(private, text, f'{what} exposes a key or token')
        if isinstance(value, dict):
            # Timestamps end in six-digit fractions that could equal a code by chance.
            text = json.dumps({key: item for key, item in value.items() if not str(key).endswith('_at')},
                              ensure_ascii=False, default=str)
        for code in sorted(self.sent_codes()):
            self.assertNotIn(code, text, f'{what} exposes a submitted code')

    def assert_storage_private(self):
        """The SQLite file (and its journal) never holds a key or token in the clear."""
        blob = b''
        for path in sorted(Path(self.tmp.name).iterdir()):
            with contextlib.suppress(OSError):  # a rollback journal may vanish while listing
                blob += path.read_bytes()
        self.assertGreater(len(blob), 0)
        for private in sorted(self.private_values()):
            self.assertEqual(blob.count(private.encode()), 0, 'plaintext key or token in the SQLite file')

    def assert_result(self, result, **expected):
        self.assertEqual({key: result.get(key) for key in expected}, expected)

    # ---- driving --------------------------------------------------------

    async def reset(self, *, email=EMAIL, server=None, db=None, check_phase=True, **options):
        """One browser task (own session and client), then the checks every run must pass."""
        server = server or self.server
        normal = email.strip().lower()
        before, first = await self.durable(normal), len(server.calls)
        client = ChatGPTMfaClient(server, expected_email=email)
        if db is not None:
            result = await totp_reset.run_reset(db, email=email, client=client, **options)
        else:
            async with self.factory() as session:
                result = await totp_reset.run_reset(session, email=email, client=client, **options)
        self.trace = server.names(first)
        await self.check_run(result, server.calls[first:], normal, before, server, check_phase)
        return result

    async def check_run(self, result, calls, email, before, server, check_phase):
        names = [call.endpoint for call in calls]
        self.assertNotIn('unknown', names, 'only the five documented endpoints may be requested')
        # Public shape of the result, and nothing secret in it, in the file or in the logs.
        self.assertIsInstance(result, dict)
        self.assertIn(result.get('status'), ('success', 'failed', 'manual_required', 'cancelled'))
        self.assertIs(result.get('ok'), result['status'] == 'success')
        self.assertIs(result.get('success'), result['ok'])
        self.assertTrue(isinstance(result.get('message'), str) and result['message'].strip())
        self.assertIsInstance(result.get('phase'), str)
        if not result['ok']:
            self.assertTrue(isinstance(result.get('error_code'), str) and result['error_code'])
        self.assert_public(result)
        self.assert_storage_private()
        self.assert_public('\n'.join(self.logged), what='log')
        # Nothing that can change the account before identity and status were read in this run.
        first = next((index for index, name in enumerate(names) if name in MUTATING), None)
        if first is not None:
            self.assertIn('session', names[:first])
            self.assertIn('info', names[:first])
        # Every change was preceded by its committed record.
        for call in calls:
            record = call.durable.record
            if call.endpoint in ('disable', 'enroll'):
                self.assertIsInstance(record, dict, f'{call.endpoint} was sent without a committed record')
                self.assertEqual(record['phase'], 'preparing', f'{call.endpoint} was sent in the wrong phase')
                self.assertFalse(record.get('secret'), 'a preparing record holds no key')
            elif call.endpoint == 'activate':
                issued = server.enrolment((call.data or {}).get('session_id'))
                self.assertIsNotNone(issued, 'activation used an enrolment session the server never issued')
                self.assertIsInstance(record, dict, 'activation was sent without a committed record')
                self.assertEqual((record['phase'], record['secret'], record['session_id']),
                                 ('activating', issued['secret'], issued['session_id']),
                                 'the key and its session must be committed before an activation is sent')
        # A held key is only ever continued: never replaced, never dropped.
        after = await self.durable(email)
        held = before.record['secret'] if isinstance(before.record, dict) and before.record['phase'] in KEYED else ''
        if held:
            self.assertNotIn('enroll', names, 'a second key was enrolled while a record was open')
            self.assertNotIn('disable', names, 'a factor was disabled while a key-bearing record was open')
        for call in calls:
            if call.endpoint == 'activate':
                held = server.enrolment(call.data['session_id'])['secret']
        if held:
            self.assertIsInstance(after.record, dict, 'the record of a key that may be live vanished')
            if after.record['phase'] == 'confirmed':
                self.assertEqual(after.backup, (held, 'official_confirmed'))
            else:
                self.assertIn(after.record['phase'], KEYED, 'a key that may be live was dropped')
                self.assertEqual(after.record['secret'], held)
        if result['ok']:
            self.assert_result(result, phase='confirmed', backup_saved=True)
            self.assertIsInstance(result.get('owner_synced'), int)
            self.assertEqual(after.record['phase'], 'confirmed')
            self.assertEqual(after.backup[1], 'official_confirmed')
            self.assertNotIn(after.backup[0], json.dumps(after.record), 'a confirmed record keeps no key')
        if check_phase and not isinstance(after.record, Exception):
            committed = after.record['phase'] if after.record else ''
            if committed in OPEN:
                self.assertEqual(result['phase'], committed, 'the result must name the committed open phase')
            else:
                self.assertNotIn(result['phase'], OPEN, 'the result claims an open phase that is not committed')

    async def reach(self, phase):
        """Drive a new reset of an account with one old factor into an open phase."""
        server = self.server
        if not server.factors:
            server.factors.append('factor-old')
        if phase == 'preparing':
            server.plan('disable', server.upcoming('disable'), reply(500, OUTAGE))
        elif phase == 'prepared':
            server.plan('activate', server.upcoming('activate'), reply(400, BAD_CODE))
        elif phase == 'activating':
            server.plan('activate', server.upcoming('activate'), dropped())
        elif phase == 'activated':
            server.plan('info', server.upcoming('info') + 1, reply(500, OUTAGE))
        else:
            raise AssertionError(phase)
        result = await self.reset()
        self.assertEqual(((await self.durable()).record or {}).get('phase'), phase)
        return result


class FreshRunTests(ResetCase):
    async def test_replaces_the_old_factor_with_a_committed_record_before_every_change(self):
        self.server.factors = ['factor-old']
        result = await self.reset()
        self.assertEqual(self.trace, FULL)
        self.assert_result(result, ok=True, success=True, status='success', phase='confirmed',
                           backup_saved=True, owner_synced=0)
        self.assertFalse(result.get('extra_factors'))
        session, info, disable, enroll, activate, confirm = self.server.calls

        # The documented requests.
        self.assertEqual((session.method, session.path, session.body), ('GET', SESSION, None))
        self.assertNotIn('authorization', session.headers)
        for call in (info, disable, enroll, activate, confirm):
            self.assertEqual(call.headers.get('authorization'), 'Bearer ' + self.server.token)
        for call in (info, confirm):
            self.assertEqual((call.method, call.path, call.body), ('GET', INFO, None))
            self.assertEqual((call.headers.get('x-openai-target-path'), call.headers.get('x-openai-target-route')),
                             (INFO, INFO))
        self.assertEqual(disable.data, {'factor_id': 'factor-old'})
        self.assertEqual(enroll.data, {'factor_type': 'totp'})
        self.assertEqual(set(activate.data), {'code', 'factor_type', 'session_id'})
        self.assertEqual((activate.data['factor_type'], activate.data['session_id']), ('totp', 'enrol-session-1'))
        self.assertRegex(activate.data['code'], r'\A\d{6}\Z')
        self.assertIn(activate.data['code'], {generate_totp(NEW_SECRET, timestamp=activate.at),
                                              generate_totp(NEW_SECRET, timestamp=activate.at - 30)})

        # What was already committed when each request arrived.
        self.assertIsNone(session.durable.record)
        self.assertIsNone(info.durable.record)
        for call in (disable, enroll):
            self.assertEqual(call.durable.record['phase'], 'preparing')
            self.assertNotIn(NEW_SECRET, json.dumps(call.durable.record))
        pending = activate.durable
        self.assertEqual((pending.record['phase'], pending.record['secret'], pending.record['session_id']),
                         ('activating', NEW_SECRET, 'enrol-session-1'))
        self.assertEqual((pending.record.get('attempts'), bool(pending.record.get('uncertain'))), (1, False))
        self.assertIsNone(pending.backup, 'an unacknowledged key is not the backup yet')
        self.assertEqual(confirm.durable.record['phase'], 'activated')
        self.assertEqual(confirm.durable.backup, (NEW_SECRET, 'official_activated'))

        # The end state.
        final = await self.durable()
        self.assertEqual(final.record['phase'], 'confirmed')
        self.assertNotIn(NEW_SECRET, json.dumps(final.record))
        self.assertEqual(final.backup, (NEW_SECRET, 'official_confirmed'))
        self.assertEqual(self.server.factors, ['factor-new-1'])
        view = await self.view()
        self.assertEqual((view['phase'], view['open'], view['has_candidate']), ('confirmed', False, False))

    async def test_account_without_2fa_skips_disable_and_syncs_every_owned_workspace(self):
        mine = await self.seed_owner(EMAIL, (OLD_SECRET, None))
        theirs = await self.seed_owner(OTHER_EMAIL, (FOREIGN_SECRET,))
        async with self.factory() as db:
            orphan = Workspace(name='Unowned', status='active', owner_totp_secret_encrypted=encrypt_secret(FOREIGN_SECRET))
            db.add(orphan)
            await db.commit()
            untouched = {row.id: row.owner_totp_secret_encrypted for row in await db.scalars(select(Workspace))
                         if row.id not in mine}
        result = await self.reset()
        self.assertEqual(self.trace, BARE)
        self.assertEqual(self.server.count('disable'), 0)
        self.assert_result(result, ok=True, status='success', phase='confirmed', backup_saved=True, owner_synced=2)
        owners = (await self.durable()).owners
        self.assertEqual([owners[item] for item in mine], [NEW_SECRET, NEW_SECRET])
        self.assertEqual([owners[item] for item in (*theirs, orphan.id)], [FOREIGN_SECRET, FOREIGN_SECRET])
        async with self.factory() as db:
            self.assertEqual({row.id: row.owner_totp_secret_encrypted for row in await db.scalars(select(Workspace))
                              if row.id not in mine}, untouched)
        # The owner keys were written by the commit that acknowledged the activation.
        self.assertEqual([self.server.calls[-1].durable.owners[item] for item in mine], [NEW_SECRET, NEW_SECRET])
        self.assertEqual([self.server.of('activate')[0].durable.owners[item] for item in mine], [OLD_SECRET, ''])

    async def test_owner_sync_counts_nothing_without_a_local_account(self):
        theirs = await self.seed_owner(OTHER_EMAIL, (FOREIGN_SECRET,))
        result = await self.reset()
        self.assert_result(result, ok=True, owner_synced=0, backup_saved=True)
        final = await self.durable()
        self.assertEqual(final.owners, {theirs[0]: FOREIGN_SECRET})
        self.assertEqual(final.backup, (NEW_SECRET, 'official_confirmed'))

    async def test_session_refusals_send_nothing_and_store_nothing(self):
        cases = [
            ('another account in user.email', {'user': {'email': OTHER_EMAIL}, 'accessToken': access_token(EMAIL)},
             'session_identity_mismatch'),
            ('another account in the token', {'user': {'email': EMAIL}, 'accessToken': access_token(OTHER_EMAIL)},
             'session_identity_mismatch'),
            ('another account in the token profile',
             {'user': {'email': EMAIL}, 'accessToken': access_token(EMAIL, profile=OTHER_EMAIL)},
             'session_identity_mismatch'),
            ('no email anywhere', {'user': {'id': 'user-fixture'}, 'accessToken': access_token(None)},
             'session_identity_mismatch'),
            ('no access token', {'user': {'email': EMAIL}}, 'session_missing'),
            ('signed out', {}, 'session_missing'),
            ('HTTP 401', reply(401, {'error': {'code': 'token_expired'}}), 'session_rejected'),
            ('HTTP 500', reply(500, OUTAGE), None),
            ('no response', dropped(), None),
            ('not a JSON object', reply(200, 'null'), None),
        ]
        for label, session, code in cases:
            with self.subTest(label):
                await self.restart(factors=['factor-old'])
                if isinstance(session, dict):
                    self.server.sign_in(session)
                else:
                    self.server.plan('session', 1, session)
                result = await self.reset()
                self.assertEqual(self.trace, ['session'])
                self.assert_result(result, ok=False, status='failed')
                if code:
                    self.assertEqual(result['error_code'], code)
                if label == 'HTTP 401':
                    self.assertEqual(result.get('remote_status'), 401)
                state = await self.durable()
                self.assertIsNone(state.record)
                self.assertIsNone(state.backup)
                self.assertEqual(await self.settings('totp_reset'), {})
                self.assertEqual(self.server.factors, ['factor-old'])

    async def test_unreadable_status_on_a_fresh_run_sends_nothing(self):
        cases = [
            ('HTTP 500', reply(500, OUTAGE)), ('no response', dropped()),
            ('HTTP 403', reply(403, {'error': {'code': 'forbidden'}})), ('HTTP 401', reply(401, {})),
            ('HTTP 429', reply(429, {})), ('redirect', reply(0, None)),
            # A 2xx without any of the known fields must never be read as "2FA is off".
            ('unrecognised object', reply(200, {})), ('unrelated object', reply(200, {'user': 'fixture'})),
            ('not an object', reply(200, [])), ('null', reply(200, 'null')),
            ('markup', reply(200, '<html>challenge</html>')),
        ]
        for label, behaviour in cases:
            for factors in (['factor-old'], []):
                with self.subTest(label, factors=factors):
                    await self.restart(factors=factors)
                    self.server.plan('info', 1, behaviour)
                    result = await self.reset()
                    self.assertEqual(self.trace, ['session', 'info'])
                    self.assert_result(result, ok=False, status='failed')
                    self.assertIsNone((await self.durable()).record)
                    self.assertEqual(await self.settings('totp_reset'), {})
                    self.assertEqual(self.server.factors, factors)

    async def test_rejected_disable_removes_the_record_and_sends_nothing_else(self):
        cases = [
            ('HTTP 403', reply(403, {'error': {'code': 'factor_locked'}})),
            ('HTTP 429', reply(429, {'error': {'code': 'slow_down'}})), ('HTTP 401', reply(401, {})),
            ('HTTP 404', reply(404, 'not found')), ('redirect', reply(0, None)),
            ('success false', reply(200, {'success': False})), ('error in a 200', reply(200, {'error': 'factor_locked'})),
        ]
        for label, behaviour in cases:
            with self.subTest(label):
                await self.restart(factors=['factor-old'])
                self.server.plan('disable', 1, behaviour)
                result = await self.reset()
                self.assertEqual(self.trace, ['session', 'info', 'disable'])
                self.assert_result(result, ok=False, status='failed', error_code='disable_rejected')
                if label == 'HTTP 403':
                    self.assert_result(result, remote_status=403, remote_code='factor_locked')
                state = await self.durable()
                self.assertIsNone(state.record)
                self.assertIsNone(state.backup)
                self.assertEqual(await self.settings('totp_reset'), {})
                self.assertEqual(self.server.factors, ['factor-old'])
                self.assertFalse((await self.view())['open'])

    async def test_unknown_disable_outcome_stays_preparing_then_restarts_from_the_status_read(self):
        cases = [
            ('HTTP 500, not applied', reply(500, OUTAGE), FULL),
            ('HTTP 502 after applying', lost(502), BARE),
            ('response lost after applying', lost(), BARE),
            ('request never arrived', dropped(), FULL),
            ('200 that is not JSON', reply(200, 'OK'), FULL),
        ]
        for label, behaviour, resumed in cases:
            with self.subTest(label):
                await self.restart(factors=['factor-old'])
                self.server.plan('disable', 1, behaviour)
                result = await self.reset()
                self.assertEqual(self.trace, ['session', 'info', 'disable'])
                self.assert_result(result, ok=False, status='manual_required', error_code='reset_interrupted',
                                   phase='preparing')
                state = await self.durable()
                self.assertEqual(state.record['phase'], 'preparing')
                self.assertFalse(state.record.get('secret'))
                self.assertIsNone(state.backup)
                view = await self.view()
                self.assertEqual((view['phase'], view['open'], view['has_candidate']), ('preparing', True, False))
                # The next task reads the truth again instead of assuming what the disable did.
                result = await self.reset()
                self.assertEqual(self.trace, resumed)
                self.assert_result(result, ok=True, phase='confirmed')
                self.assertEqual(self.server.count('enroll'), 1)
                self.assertEqual(self.server.factors, ['factor-new-1'])
                self.assertEqual((await self.durable()).backup, (NEW_SECRET, 'official_confirmed'))

    async def test_failed_enrolment_after_a_disable_stays_preparing_and_recovers(self):
        cases = [
            ('rejected', reply(400, {'error': {'code': 'enrollment_unavailable'}})),
            ('HTTP 500', reply(500, OUTAGE)), ('no response', dropped()),
            ('response lost after applying', lost()),
            ('unusable key', reply(200, {'secret': 'not-a-key', 'session_id': 'enrol-session-x', 'factor': {'id': 'x'}})),
            ('no enrolment session', reply(200, {'secret': THIRD_SECRET, 'factor': {'id': 'factor-x'}})),
            ('200 that is not JSON', reply(200, 'OK')),
        ]
        for label, behaviour in cases:
            with self.subTest(label):
                await self.restart(factors=['factor-old'])
                self.server.plan('enroll', 1, behaviour)
                result = await self.reset()
                self.assertEqual(self.trace, ['session', 'info', 'disable', 'enroll'])
                self.assert_result(result, ok=False, status='manual_required', error_code='enroll_failed',
                                   phase='preparing')
                state = await self.durable()
                self.assertEqual(state.record['phase'], 'preparing')
                self.assertFalse(state.record.get('secret'))
                self.assertIsNone(state.backup)
                self.assertEqual(self.server.factors, [], 'the old factor is already gone')
                result = await self.reset()
                self.assertEqual(self.trace, BARE)
                self.assert_result(result, ok=True, phase='confirmed')
                issued = self.server.enrolments[-1]
                self.assertEqual((await self.durable()).backup, (issued['secret'], 'official_confirmed'))
                self.assertEqual(self.server.factors, [issued['factor_id']])

    async def test_rejected_enrolment_without_an_old_factor_removes_the_record(self):
        cases = [
            ('HTTP 403', reply(403, {'error': {'code': 'mfa_not_allowed'}})), ('HTTP 429', reply(429, {})),
            ('HTTP 401', reply(401, {})), ('redirect', reply(0, None)), ('success false', reply(200, {'success': False})),
        ]
        for label, behaviour in cases:
            with self.subTest(label):
                await self.restart()
                self.server.plan('enroll', 1, behaviour)
                result = await self.reset()
                self.assertEqual(self.trace, ['session', 'info', 'enroll'])
                self.assert_result(result, ok=False, status='failed', error_code='enroll_rejected')
                if label == 'HTTP 403':
                    self.assert_result(result, remote_status=403, remote_code='mfa_not_allowed')
                state = await self.durable()
                self.assertIsNone(state.record)
                self.assertIsNone(state.backup)
                self.assertEqual(await self.settings('totp_reset'), {})

    async def test_unknown_enrolment_outcome_without_an_old_factor_never_activates(self):
        cases = [
            ('HTTP 500', reply(500, OUTAGE)), ('no response', dropped()), ('response lost after applying', lost()),
            ('unusable key', reply(200, {'secret': '123456', 'session_id': 'enrol-session-x'})),
        ]
        for label, behaviour in cases:
            with self.subTest(label):
                await self.restart()
                self.server.plan('enroll', 1, behaviour)
                result = await self.reset()
                self.assertEqual(self.trace, ['session', 'info', 'enroll'])
                self.assertFalse(result['ok'])
                state = await self.durable()
                self.assertFalse(state.record and state.record.get('secret'))
                self.assertIsNone(state.backup)
                result = await self.reset()
                self.assertEqual(self.trace, BARE)
                self.assert_result(result, ok=True, phase='confirmed')
                self.assertEqual((await self.durable()).backup,
                                 (self.server.enrolments[-1]['secret'], 'official_confirmed'))

    async def test_other_listed_factors_are_reported_as_extra_factors(self):
        for with_id in (True, False):
            with self.subTest(enrol_names_the_factor=with_id):
                await self.restart(factors=['factor-old', 'factor-spare'])
                self.server.return_factor_id = with_id
                result = await self.reset()
                self.assertEqual(self.trace, FULL)
                self.assertEqual(self.server.of('disable')[0].data, {'factor_id': 'factor-old'})
                self.assertEqual(self.server.factors, ['factor-spare', 'factor-new-1'])
                self.assert_result(result, ok=True, phase='confirmed', extra_factors=1)

    async def test_a_closed_record_lets_the_next_run_start_fresh(self):
        self.server.factors = ['factor-old']
        self.assertTrue((await self.reset())['ok'])
        result = await self.reset()
        self.assertEqual(self.trace, FULL)
        self.assert_result(result, ok=True, phase='confirmed')
        self.assertEqual(self.server.of('disable')[-1].data, {'factor_id': 'factor-new-1'})
        self.assertEqual(self.server.factors, ['factor-new-2'])
        self.assertEqual(self.server.count('enroll'), 2)
        final = await self.durable()
        self.assertEqual(final.record['phase'], 'confirmed')
        self.assertEqual(final.backup, (SECOND_SECRET, 'official_confirmed'))

    async def test_email_spelling_maps_to_one_encrypted_record(self):
        # The signed-in session spells the address differently: identity is compared case-insensitively.
        self.server = self.new_server(email='Owner@Example.COM', factors=['factor-old'])
        self.server.plan('activate', 1, reply(400, BAD_CODE))
        result = await self.reset(email='  OWNER@example.com ')
        self.assert_result(result, ok=False, error_code='activation_rejected', phase='prepared')
        rows = await self.settings('totp_reset')
        self.assertEqual(list(rows), [reset_key(EMAIL)])
        stored = json.loads(token_cipher().decrypt(rows[reset_key(EMAIL)]))
        self.assertEqual((stored['email'], stored['phase']), (EMAIL, 'prepared'))
        self.assertEqual((await self.view(' Owner@EXAMPLE.com'))['phase'], 'prepared')
        revealed = await self.call(totp_reset.reveal_candidate, email='OWNER@EXAMPLE.COM')
        self.assertEqual((revealed['email'], revealed['secret']), (EMAIL, NEW_SECRET))
        result = await self.reset(email='Owner@Example.com')
        self.assert_result(result, ok=True, phase='confirmed')
        self.assertEqual(list(await self.settings('totp_reset')), [reset_key(EMAIL)])
        self.assertEqual(self.server.count('enroll'), 1)
        backup = await self.call(totp_backup.reveal_backup, email='OWNER@example.COM')
        self.assertEqual((backup['email'], backup['secret'], backup['verification']),
                         (EMAIL, NEW_SECRET, 'official_confirmed'))

    async def test_records_and_backups_are_kept_per_email(self):
        await self.reach('prepared')
        other = self.new_server(email=OTHER_EMAIL, factors=['factor-theirs'], keys=(SECOND_SECRET,),
                                probe=lambda: self.durable(OTHER_EMAIL))
        result = await self.reset(email=OTHER_EMAIL, server=other)
        self.assertEqual(self.trace, FULL)
        self.assert_result(result, ok=True, phase='confirmed')
        mine, theirs = await self.durable(EMAIL), await self.durable(OTHER_EMAIL)
        self.assertEqual((mine.record['phase'], mine.record['secret'], mine.backup), ('prepared', NEW_SECRET, None))
        self.assertEqual((theirs.record['phase'], theirs.backup), ('confirmed', (SECOND_SECRET, 'official_confirmed')))
        self.assertEqual(sorted(await self.settings('totp_reset:')), sorted((reset_key(EMAIL), reset_key(OTHER_EMAIL))))
        # A session of the other account can never continue this email's record.
        result = await self.reset(email=EMAIL, server=other)
        self.assertEqual(self.trace, ['session'])
        self.assert_result(result, ok=False, error_code='session_identity_mismatch')
        self.assertEqual((await self.durable(EMAIL)).record, mine.record)

    async def test_remote_error_text_never_reaches_the_result(self):
        hostile = [
            {'error': {'code': 'bad code <script>', 'message': 'REMOTE-BODY-TEXT ' + NEW_SECRET}, 'detail': 'REMOTE-BODY-TEXT'},
            {'detail': {'code': 'x' * 81, 'msg': 'REMOTE-BODY-TEXT'}},
            {'code': 'REMOTE-BODY-TEXT!', 'error': 'REMOTE-BODY-TEXT ' + access_token(EMAIL)},
            'REMOTE-BODY-TEXT <html>',
        ]
        messages = set()
        for index, body in enumerate(hostile):
            with self.subTest(hostile=index):
                await self.restart(factors=['factor-old'])
                self.server.plan('disable', 1, reply(403, body))
                result = await self.reset()
                text = json.dumps(result, ensure_ascii=False)
                self.assertNotIn('REMOTE-BODY-TEXT', text)
                self.assertNotIn('script', text)
                self.assertRegex(result.get('remote_code') or '', r'\A[A-Za-z0-9_]{0,80}\Z')
                self.assert_result(result, error_code='disable_rejected', remote_status=403)
                self.assertRegex(result['message'], '[一-鿿]')
                messages.add(result['message'])
        self.assertEqual(len(messages), 1, 'the message is a fixed sentence, whatever the server said')
        # A well-formed remote code is passed on from each documented place.
        for body in ({'error': {'code': 'factor_locked'}}, {'detail': {'code': 'factor_locked'}}, {'code': 'factor_locked'}):
            with self.subTest(body=body):
                await self.restart(factors=['factor-old'])
                self.server.plan('disable', 1, reply(403, body))
                self.assert_result(await self.reset(), remote_status=403, remote_code='factor_locked')

    async def test_progress_notes_and_operation_row_hold_no_secret(self):
        hostile = {'error': {'code': 'factor_locked', 'message': 'REMOTE-BODY-TEXT ' + NEW_SECRET}}
        for label, expected in (('success', 'success'), ('failure', 'failed')):
            with self.subTest(label):
                await self.restart(factors=['factor-old'])
                if label == 'failure':
                    self.server.plan('disable', 1, reply(403, hostile))
                stages = []
                async with self.factory() as db:
                    operation = await operation_store.create(db, op_type='assisted_login', email=EMAIL,
                                                             input_payload={'action': 'reset_totp', 'mode': 'fresh'})
                    public_id = operation.public_id
                    await db.commit()

                    async def report(stage):
                        stages.append(stage)
                        row = await operation_store.get_by_public_id(db, public_id)
                        await operation_store.note(db, row, stage, assisted_login.MESSAGES[stage])
                        await db.commit()

                    result = await self.reset(db=db, operation_id=public_id, report=report)
                    row = await operation_store.get_by_public_id(db, public_id)
                    await operation_store.finish(db, row, result)
                    await db.commit()
                async with self.factory() as db:
                    row = await operation_store.get_by_public_id(db, public_id)
                    stored = {'state': row.state, 'input_json': row.input_json, 'result_json': row.result_json,
                              'log_json': row.log_json, 'error_message': row.error_message,
                              'error_code': row.error_code, 'current_step': row.current_step}
                self.assertEqual(stored['state'], expected)
                self.assertTrue(stages)
                for stage in stages:
                    # Every stage has a fixed progress sentence, and the note was really written.
                    self.assertIn(stage, assisted_login.MESSAGES)
                    self.assertIn(stage, stored['log_json'])
                self.assert_public(json.dumps(stored, ensure_ascii=False), what='operation row')
                self.assertNotIn('REMOTE-BODY-TEXT', json.dumps(stored, ensure_ascii=False))
                self.assert_public(' '.join(stages), what='progress stage')
                self.assert_storage_private()

    async def test_a_failing_progress_reporter_does_not_change_the_outcome(self):
        self.server.factors = ['factor-old']
        seen = []

        def report(stage):
            seen.append(stage)
            raise RuntimeError('synthetic reporter failure')

        result = await self.reset(report=report)
        self.assertEqual(self.trace, FULL)
        self.assert_result(result, ok=True, phase='confirmed')
        self.assertTrue(seen)
        self.assertEqual((await self.durable()).backup, (NEW_SECRET, 'official_confirmed'))

    async def test_one_long_lived_session_can_serve_a_whole_recovery(self):
        self.server.factors = ['factor-old']
        self.server.plan('activate', 1, reply(400, BAD_CODE))
        async with self.factory() as db:
            self.assert_result(await self.reset(db=db), ok=False, error_code='activation_rejected', phase='prepared')
            self.assertEqual((await totp_reset.status_reset(db, email=EMAIL))['phase'], 'prepared')
            self.assertEqual((await totp_reset.reveal_candidate(db, email=EMAIL))['secret'], NEW_SECRET)
            with self.assertRaises(CredentialImportError) as caught:
                await totp_backup.save_backup(db, email=EMAIL, secret=MANUAL_SECRET, confirmed=True)
            self.assertEqual(caught.exception.code, 'reset_pending')
            self.assert_result(await self.reset(db=db), ok=True, phase='confirmed')
            self.assertEqual(self.trace, ['session', 'info', 'activate', 'info'])
            view = await totp_reset.status_reset(db, email=EMAIL)
            self.assertEqual((view['phase'], view['open'], view['exported']), ('confirmed', False, True))
            backup = await totp_backup.reveal_backup(db, email=EMAIL)
            self.assertEqual((backup['secret'], backup['verification']), (NEW_SECRET, 'official_confirmed'))
            await totp_backup.save_backup(db, email=EMAIL, secret=MANUAL_SECRET, confirmed=True)
            self.assertEqual(await totp_backup.stored_secret(db, EMAIL), MANUAL_SECRET)
            self.assert_result(await self.reset(db=db), ok=True, phase='confirmed')
            self.assertEqual(self.trace, FULL)
            backup = await totp_backup.reveal_backup(db, email=EMAIL)
            self.assertEqual((backup['secret'], backup['verification']), (SECOND_SECRET, 'official_confirmed'))
        self.assertEqual((await self.durable()).backup, (SECOND_SECRET, 'official_confirmed'))


class ActivationOutcomeTests(ResetCase):
    async def test_rejected_first_activation_returns_to_prepared_and_resumes_with_the_stored_session(self):
        self.server.factors = ['factor-old']
        self.server.plan('activate', 1, reply(400, BAD_CODE))
        result = await self.reset()
        self.assertEqual(self.trace, ['session', 'info', 'disable', 'enroll', 'activate'])
        self.assert_result(result, ok=False, status='manual_required', error_code='activation_rejected',
                           phase='prepared', remote_status=400, remote_code='invalid_code')
        state = await self.durable()
        self.assertEqual((state.record['phase'], state.record['secret'], state.record['session_id']),
                         ('prepared', NEW_SECRET, 'enrol-session-1'))
        self.assertIsNone(state.backup, 'a key that is not live is not the backup')
        view = await self.view()
        self.assertEqual((view['phase'], view['open'], view['has_candidate']), ('prepared', True, True))

        result = await self.reset()
        self.assertEqual(self.trace, ['session', 'info', 'activate', 'info'], 'status is read before anything is sent')
        self.assert_result(result, ok=True, status='success', phase='confirmed', backup_saved=True)
        first, second = self.server.of('activate')
        self.assertEqual(second.data['session_id'], first.data['session_id'])
        self.assertEqual(second.data['session_id'], 'enrol-session-1')
        self.assertEqual((second.durable.record['phase'], second.durable.record.get('attempts')), ('activating', 2))
        self.assertEqual(self.server.count('enroll'), 1)
        self.assertEqual(self.server.count('disable'), 1)
        final = await self.durable()
        self.assertEqual((final.record['phase'], final.backup), ('confirmed', (NEW_SECRET, 'official_confirmed')))
        self.assertEqual(self.server.factors, ['factor-new-1'])

    async def test_lost_activation_response_is_settled_by_the_status_read(self):
        for label, behaviour in (('response lost', lost()), ('HTTP 500', lost(500)), ('HTTP 504', lost(504))):
            with self.subTest(label):
                await self.restart(factors=['factor-old'])
                self.server.plan('activate', 1, behaviour)
                result = await self.reset()
                self.assertEqual(self.trace, FULL)
                self.assert_result(result, ok=True, status='success', phase='confirmed', backup_saved=True)
                waiting = self.server.calls[-1].durable
                self.assertEqual((waiting.record['phase'], waiting.record['secret'], waiting.record.get('uncertain')),
                                 ('activating', NEW_SECRET, True))
                self.assertIsNone(waiting.backup)
                final = await self.durable()
                self.assertEqual((final.record['phase'], final.backup), ('confirmed', (NEW_SECRET, 'official_confirmed')))
                self.assertEqual(self.server.count('activate'), 1)

    async def test_lost_response_with_a_failed_status_read_stays_activating_and_is_finalised_without_resending(self):
        for label, failure in (('HTTP 500', reply(500, OUTAGE)), ('no response', dropped())):
            with self.subTest(status_read=label):
                await self.restart(factors=['factor-old'])
                self.server.plan('activate', 1, lost())
                self.server.plan('info', 2, failure)
                result = await self.reset()
                self.assertEqual(self.trace, FULL)
                self.assert_result(result, ok=False, status='manual_required', error_code='activation_unconfirmed',
                                   phase='activating')
                state = await self.durable()
                self.assertEqual((state.record['phase'], state.record['secret'], state.record.get('uncertain')),
                                 ('activating', NEW_SECRET, True))
                self.assertIsNone(state.backup)
                view = await self.view()
                self.assertEqual((view['phase'], view['open'], view['has_candidate']), ('activating', True, True))

                result = await self.reset()
                self.assertEqual(self.trace, ['session', 'info'], 'the factor is live: nothing may be sent again')
                self.assert_result(result, ok=True, status='success', phase='confirmed', backup_saved=True)
                self.assertEqual((self.server.count('activate'), self.server.count('enroll')), (1, 1))
                final = await self.durable()
                self.assertEqual((final.record['phase'], final.backup), ('confirmed', (NEW_SECRET, 'official_confirmed')))

    async def test_activation_that_never_arrived_is_sent_again_with_the_stored_session(self):
        self.server.factors = ['factor-old']
        self.server.plan('activate', 1, dropped())
        result = await self.reset()
        self.assertEqual(self.trace, FULL)
        self.assert_result(result, ok=False, status='manual_required', error_code='activation_unconfirmed',
                           phase='activating')
        state = await self.durable()
        self.assertEqual((state.record['phase'], state.record['secret']), ('activating', NEW_SECRET))
        self.assertEqual(self.server.factors, [])

        result = await self.reset()
        self.assertEqual(self.trace, ['session', 'info', 'activate', 'info'])
        self.assert_result(result, ok=True, status='success', phase='confirmed')
        first, second = self.server.of('activate')
        self.assertEqual(second.data['session_id'], first.data['session_id'])
        self.assertEqual((second.durable.record.get('attempts'), second.durable.record.get('uncertain')), (2, True))
        self.assertEqual(self.server.count('enroll'), 1)
        self.assertEqual((await self.durable()).backup, (NEW_SECRET, 'official_confirmed'))
        self.assertEqual(self.server.factors, ['factor-new-1'])

    async def test_rejection_after_an_uncertain_attempt_never_returns_to_prepared(self):
        await self.reach('activating')
        self.server.plan('activate', 2, reply(400, BAD_CODE))
        result = await self.reset()
        self.assertEqual(self.trace, ['session', 'info', 'activate', 'info'])
        self.assert_result(result, ok=False, status='manual_required', phase='activating')
        state = await self.durable()
        self.assertEqual((state.record['phase'], state.record['secret'], state.record.get('uncertain')),
                         ('activating', NEW_SECRET, True))
        self.assertIsNone(state.backup)
        result = await self.reset()
        self.assertEqual(self.trace, ['session', 'info', 'activate', 'info'])
        self.assert_result(result, ok=True, phase='confirmed')
        self.assertEqual(self.server.count('enroll'), 1)

    async def test_stale_status_then_rejected_retry_is_settled_by_the_confirming_read(self):
        self.server.factors = ['factor-old']
        self.server.plan('activate', 1, lost())           # applied, response lost
        self.server.plan('info', 2, reply(500, OUTAGE))   # and the check right after it fails
        self.assert_result(await self.reset(), ok=False, error_code='activation_unconfirmed', phase='activating')
        self.assertEqual(self.server.factors, ['factor-new-1'])
        self.server.plan('info', 3, reply(200, NO_2FA))   # a stale read on the next task
        result = await self.reset()
        # The retry is refused (the session was already used), yet the key is live: it must not be demoted.
        self.assertEqual(self.trace, ['session', 'info', 'activate', 'info'])
        self.assert_result(result, ok=True, status='success', phase='confirmed')
        self.assertEqual(self.server.count('enroll'), 1)
        self.assertEqual((await self.durable()).backup, (NEW_SECRET, 'official_confirmed'))

    async def test_acknowledged_activation_survives_a_failed_status_read(self):
        for label, failure in (('HTTP 500', reply(500, OUTAGE)), ('no response', dropped())):
            with self.subTest(status_read=label):
                await self.restart(factors=['factor-old'])
                mine = await self.seed_owner(EMAIL, (OLD_SECRET, None))
                self.server.plan('info', 2, failure)
                result = await self.reset()
                self.assertEqual(self.trace, FULL)
                self.assert_result(result, ok=False, status='manual_required', error_code='confirm_pending',
                                   phase='activated', backup_saved=True)
                state = await self.durable()
                self.assertEqual((state.record['phase'], state.record['secret']), ('activated', NEW_SECRET))
                self.assertEqual(state.backup, (NEW_SECRET, 'official_activated'))
                self.assertEqual([state.owners[item] for item in mine], [NEW_SECRET, NEW_SECRET])
                view = await self.view()
                self.assertEqual((view['phase'], view['open'], view['has_candidate']), ('activated', True, True))

                result = await self.reset()
                self.assertEqual(self.trace, ['session', 'info'], 'an acknowledged activation is only checked')
                self.assert_result(result, ok=True, status='success', phase='confirmed', backup_saved=True,
                                   owner_synced=2)
                self.assertEqual((self.server.count('activate'), self.server.count('enroll')), (1, 1))
                final = await self.durable()
                self.assertEqual((final.record['phase'], final.backup), ('confirmed', (NEW_SECRET, 'official_confirmed')))
                self.assertEqual([final.owners[item] for item in mine], [NEW_SECRET, NEW_SECRET])

    async def test_unrelated_factor_does_not_confirm_until_login_proof(self):
        self.server.factors = ['factor-old']
        self.server.listed_as = 'factor-unrelated'
        result = await self.reset()
        self.assertEqual(self.trace, FULL)
        self.assert_result(result, ok=False, status='manual_required', error_code='confirm_mismatch',
                           phase='activated', backup_saved=True)
        self.assertEqual((await self.durable()).backup, (NEW_SECRET, 'official_activated'))
        result = await self.reset()
        self.assertEqual(self.trace, ['session', 'info'])
        self.assert_result(result, ok=False, status='manual_required', error_code='confirm_mismatch', phase='activated')
        state = await self.durable()
        self.assertEqual((state.record['phase'], state.record['secret']), ('activated', NEW_SECRET))
        # This session signed in with a code from the stored key: that proves it is the live one.
        result = await self.reset(login_proof=True)
        self.assertEqual(self.trace, ['session', 'info'])
        self.assert_result(result, ok=True, status='success', phase='confirmed', backup_saved=True)
        self.assertEqual((await self.durable()).backup, (NEW_SECRET, 'official_confirmed'))
        self.assertEqual((self.server.count('activate'), self.server.count('enroll')), (1, 1))

    async def test_missing_factor_id_is_confirmed_by_acknowledgement_plus_enabled(self):
        self.server.factors = ['factor-old']
        self.server.return_factor_id = False
        result = await self.reset()
        self.assertEqual(self.trace, FULL)
        self.assert_result(result, ok=True, status='success', phase='confirmed', backup_saved=True)
        self.assertFalse(result.get('extra_factors'))

        # Acknowledged, but the status does not show 2FA enabled yet: not confirmed.
        await self.restart(factors=['factor-old'])
        self.server.return_factor_id = False
        self.server.plan('info', 2, reply(200, NO_2FA))
        result = await self.reset()
        self.assert_result(result, ok=False, status='manual_required', error_code='confirm_mismatch', phase='activated')
        result = await self.reset()
        self.assertEqual(self.trace, ['session', 'info'])
        self.assert_result(result, ok=True, phase='confirmed')

    async def test_missing_factor_id_with_a_lost_activation_needs_login_proof(self):
        self.server.factors = ['factor-old']
        self.server.return_factor_id = False
        self.server.plan('activate', 1, lost())
        result = await self.reset()
        self.assertEqual(self.trace, FULL)
        self.assert_result(result, ok=False, status='manual_required', error_code='activation_unconfirmed',
                           phase='activating')
        # 2FA is on, but nothing ties it to the stored key: no request that changes anything.
        result = await self.reset()
        self.assertEqual(self.trace, ['session', 'info'])
        self.assert_result(result, ok=False, status='manual_required', error_code='factor_unmatched', phase='activating')
        state = await self.durable()
        self.assertEqual((state.record['phase'], state.record['secret']), ('activating', NEW_SECRET))
        self.assertIsNone(state.backup)
        result = await self.reset(login_proof=True)
        self.assertEqual(self.trace, ['session', 'info'])
        self.assert_result(result, ok=True, status='success', phase='confirmed', backup_saved=True)
        self.assertEqual((await self.durable()).backup, (NEW_SECRET, 'official_confirmed'))
        self.assertEqual((self.server.count('activate'), self.server.count('enroll')), (1, 1))

    async def test_login_proof_does_not_finalise_a_prepared_record(self):
        await self.reach('prepared')
        self.server.factors = ['factor-unrelated']   # 2FA is on, through a factor this record knows nothing about
        self.server.plan('activate', 2, reply(400, BAD_CODE))
        result = await self.reset(login_proof=True)
        self.assertEqual(self.trace, ['session', 'info', 'activate'], 'the proof must not replace the activation')
        self.assert_result(result, ok=False, status='manual_required', error_code='activation_rejected', phase='prepared')
        state = await self.durable()
        self.assertEqual((state.record['phase'], state.record['secret']), ('prepared', NEW_SECRET))
        self.assertIsNone(state.backup)
        # A fresh run is not finalised by it either: it does the whole exchange.
        await self.restart(factors=['factor-old'])
        result = await self.reset(login_proof=True)
        self.assertEqual(self.trace, FULL)
        self.assert_result(result, ok=True, phase='confirmed')

    async def test_login_proof_cannot_confirm_an_activation_this_run_sent_without_an_answer(self):
        """The proof speaks for the key stored when the session signed in (activating/activated).

        A record that was absent or only 'prepared' at that moment was not proven by the sign-in;
        an activation of this run that got no answer must still be settled by the status read.
        """
        for label in ('prepared record', 'fresh run'):
            with self.subTest(label):
                await self.restart(factors=['factor-old'])
                if label == 'prepared record':
                    await self.reach('prepared')
                self.server.plan('activate', self.server.upcoming('activate'), dropped())
                result = await self.reset(login_proof=True)
                self.assertEqual(self.server.factors, [], 'the account has no active factor at all')
                self.assertFalse(result['ok'], 'confirmed although the activation never arrived and 2FA is off')
                state = await self.durable()
                self.assertEqual((state.record['phase'], state.record['secret']), ('activating', NEW_SECRET))
                self.assertIsNone(state.backup, 'a key that is not live became the official backup')

    async def test_resume_sends_nothing_when_identity_or_status_cannot_be_read(self):
        for phase in KEYED:
            for label in ('another account', 'status unavailable'):
                with self.subTest(phase=phase, failure=label):
                    await self.restart()
                    await self.reach(phase)
                    before = await self.durable()
                    if label == 'another account':
                        self.server.sign_in({'user': {'email': OTHER_EMAIL}, 'accessToken': access_token(OTHER_EMAIL)})
                        expected = ['session']
                    else:
                        self.server.plan('info', self.server.upcoming('info'), reply(503, OUTAGE))
                        expected = ['session', 'info']
                    result = await self.reset(login_proof=True)
                    self.assertEqual(self.trace, expected)
                    self.assertFalse(result['ok'])
                    if label == 'another account':
                        self.assertEqual(result['error_code'], 'session_identity_mismatch')
                    after = await self.durable()
                    self.assertEqual((after.record, after.backup), (before.record, before.backup))

    async def test_interrupted_requests_are_recovered_from_the_committed_record(self):
        cases = [('disable', 'preparing', BARE), ('enroll', 'preparing', BARE), ('activate', 'activating', ['session', 'info'])]
        for endpoint, phase, resumed in cases:
            with self.subTest(interrupted=endpoint):
                await self.restart(factors=['factor-old'])
                self.server.plan(endpoint, 1, stalled())
                client = ChatGPTMfaClient(self.server, expected_email=EMAIL)

                async def task():
                    async with self.factory() as db:
                        return await totp_reset.run_reset(db, email=EMAIL, client=client)

                running = asyncio.create_task(task())
                await asyncio.wait_for(self.server.stalled.wait(), 5)
                running.cancel()  # the browser task is torn down while the request is in flight
                await asyncio.gather(running, return_exceptions=True)
                state = await self.durable()
                self.assertEqual(state.record['phase'], phase)
                self.assertEqual(state.record.get('secret') or '', NEW_SECRET if endpoint == 'activate' else '')
                self.assert_storage_private()
                result = await self.reset()
                self.assertEqual(self.trace, resumed)
                self.assert_result(result, ok=True, phase='confirmed')
                self.assertEqual((await self.durable()).backup,
                                 (self.server.enrolments[-1]['secret'], 'official_confirmed'))
                self.assertEqual(self.server.count('activate'), 1)


class AbortTests(ResetCase):
    def once(self, *endpoints):
        """should_abort() that turns true as soon as a request to one of these endpoints arrived."""
        return lambda: any(self.server.count(endpoint) for endpoint in endpoints)

    async def test_abort_before_any_change_sends_nothing(self):
        for label, should_abort, expected in (('at once', lambda: True, ['session']),
                                              ('after the status read', self.once('info'), ['session', 'info'])):
            with self.subTest(label):
                await self.restart(factors=['factor-old'])
                result = await self.reset(should_abort=should_abort)
                self.assertEqual(self.trace, expected)
                self.assert_result(result, ok=False, status='cancelled')
                self.assertIsNone((await self.durable()).record)
                self.assertEqual(await self.settings('totp_reset'), {})
                self.assertEqual(self.server.factors, ['factor-old'])

    async def test_abort_after_the_first_change_is_ignored(self):
        for factors, expected in ((['factor-old'], FULL), ([], BARE)):
            with self.subTest(factors=factors):
                await self.restart(factors=factors)
                result = await self.reset(should_abort=self.once(*MUTATING))
                self.assertEqual(self.trace, expected)
                self.assert_result(result, ok=True, status='success', phase='confirmed')
                self.assertEqual(self.server.factors, ['factor-new-1'])

    async def test_abort_on_resume_is_honoured_until_the_activation_leaves(self):
        await self.reach('prepared')
        before = await self.durable()
        for should_abort, expected in ((lambda: True, ['session']), (lambda: self.server.count('info') > 1, ['session', 'info'])):
            result = await self.reset(should_abort=should_abort)
            self.assertEqual(self.trace, expected)
            self.assert_result(result, ok=False, status='cancelled', phase='prepared')
            self.assertEqual((await self.durable()).record, before.record)
        result = await self.reset(should_abort=lambda: self.server.count('activate') > 1)
        self.assertEqual(self.trace, ['session', 'info', 'activate', 'info'])
        self.assert_result(result, ok=True, status='success', phase='confirmed')


class StorageFailureTests(ResetCase):
    @contextlib.contextmanager
    def failing_writes(self, phase, times=50):
        """Make the reset module's own write of a record in this phase fail ``times`` times."""
        real, failed = totp_reset.upsert_setting, []

        async def write(db, key, value, *args, **kwargs):
            try:
                written = json.loads(token_cipher().decrypt(value)).get('phase')
            except Exception:
                written = None
            if written == phase and len(failed) < times:
                failed.append(written)
                raise OSError('synthetic write failure near ' + NEW_SECRET)
            return await real(db, key, value, *args, **kwargs)

        with patch.object(totp_reset, 'upsert_setting', write):
            yield failed

    async def test_uncommitted_prepared_record_means_no_activation(self):
        self.server.factors = ['factor-old']
        with self.failing_writes('prepared') as failed:
            result = await self.reset()
        self.assertTrue(failed)
        self.assertEqual(self.trace, ['session', 'info', 'disable', 'enroll'], 'activation must never be sent')
        self.assert_result(result, ok=False, error_code='reset_storage_failed')
        state = await self.durable()
        self.assertEqual(state.record['phase'], 'preparing')
        self.assertFalse(state.record.get('secret'))
        self.assertIsNone(state.backup)
        self.assertEqual(self.server.factors, [])
        # The lost key was never live; the next task enrols one that is stored first.
        result = await self.reset()
        self.assertEqual(self.trace, BARE)
        self.assert_result(result, ok=True, phase='confirmed')
        self.assertEqual((await self.durable()).backup, (SECOND_SECRET, 'official_confirmed'))

    async def test_a_brief_write_failure_is_retried(self):
        self.server.factors = ['factor-old']
        with self.failing_writes('prepared', times=1) as failed:
            result = await self.reset()
        self.assertEqual(failed, ['prepared'])
        self.assertEqual(self.trace, FULL)
        self.assert_result(result, ok=True, phase='confirmed')
        self.assertEqual(self.server.count('enroll'), 1)

    async def test_failed_first_write_sends_no_change(self):
        self.server.factors = ['factor-old']
        with self.failing_writes('preparing') as failed:
            result = await self.reset(check_phase=False)
        self.assertTrue(failed)
        self.assertEqual(self.trace, ['session', 'info'])
        self.assert_result(result, ok=False, error_code='reset_storage_failed')
        self.assertIsNone((await self.durable()).record)
        self.assertEqual(self.server.factors, ['factor-old'])

    async def test_uncommitted_activating_record_means_no_activation(self):
        self.server.factors = ['factor-old']
        with self.failing_writes('activating') as failed:
            result = await self.reset()
        self.assertTrue(failed)
        self.assertEqual(self.trace, ['session', 'info', 'disable', 'enroll'])
        self.assert_result(result, ok=False, status='manual_required', error_code='reset_storage_failed', phase='prepared')
        state = await self.durable()
        self.assertEqual((state.record['phase'], state.record['secret']), ('prepared', NEW_SECRET))
        # On a later task too: the write fails again, so the stored key is still not activated.
        with self.failing_writes('activating'):
            result = await self.reset(check_phase=False)
        self.assertEqual(self.trace, ['session', 'info'])
        self.assert_result(result, ok=False, error_code='reset_storage_failed')
        self.assertEqual((await self.durable()).record, state.record)
        result = await self.reset()
        self.assertEqual(self.trace, ['session', 'info', 'activate', 'info'])
        self.assert_result(result, ok=True, phase='confirmed')
        self.assertEqual(self.server.count('enroll'), 1)

    async def test_storage_failure_reports_the_phase_that_is_actually_committed(self):
        for label in ('first write of a fresh run', 'resume of a prepared record'):
            with self.subTest(label):
                await self.restart(factors=['factor-old'])
                if label == 'first write of a fresh run':
                    failing = 'preparing'
                else:
                    await self.reach('prepared')
                    failing = 'activating'
                with self.failing_writes(failing):
                    result = await self.reset(check_phase=False)
                self.assertEqual(result['error_code'], 'reset_storage_failed')
                self.assertNotIn(self.trace[-1], MUTATING)
                committed = (await self.durable()).record
                if committed is None:
                    # Nothing was stored and nothing was sent: there is no open reset to continue.
                    self.assertNotIn(result['phase'], OPEN)
                    self.assertEqual(result['status'], 'failed')
                else:
                    self.assertEqual(result['phase'], committed['phase'])

    async def test_unacknowledged_commit_keeps_backup_and_owner_keys_untouched(self):
        self.server.factors = ['factor-old']
        mine = await self.seed_owner(EMAIL, (OLD_SECRET, None))
        await self.call(totp_backup.save_backup, email=EMAIL, secret=OLD_SECRET, confirmed=True)
        with self.failing_writes('activated') as failed:
            result = await self.reset()
        self.assertTrue(failed)
        # The acknowledgement could not be stored, so not even the status read follows.
        self.assertEqual(self.trace, ['session', 'info', 'disable', 'enroll', 'activate'])
        self.assert_result(result, ok=False, status='manual_required', error_code='reset_storage_failed',
                           phase='activating')
        state = await self.durable()
        self.assertEqual((state.record['phase'], state.record['secret']), ('activating', NEW_SECRET))
        # Record, backup and owner keys move together or not at all.
        self.assertEqual(state.backup, (OLD_SECRET, 'user_reported'))
        self.assertEqual([state.owners[item] for item in mine], [OLD_SECRET, ''])
        self.assertEqual(self.server.factors, ['factor-new-1'])
        result = await self.reset()
        self.assertEqual(self.trace, ['session', 'info'])
        self.assert_result(result, ok=True, phase='confirmed', owner_synced=2)
        final = await self.durable()
        self.assertEqual(final.backup, (NEW_SECRET, 'official_confirmed'))
        self.assertEqual([final.owners[item] for item in mine], [NEW_SECRET, NEW_SECRET])

    async def test_unconfirmed_commit_keeps_the_activated_record_and_its_key(self):
        self.server.factors = ['factor-old']
        with self.failing_writes('confirmed') as failed:
            result = await self.reset()
        self.assertTrue(failed)
        self.assertEqual(self.trace, FULL)
        self.assert_result(result, ok=False, status='manual_required', error_code='reset_storage_failed',
                           phase='activated')
        state = await self.durable()
        self.assertEqual((state.record['phase'], state.record['secret']), ('activated', NEW_SECRET))
        self.assertEqual(state.backup, (NEW_SECRET, 'official_activated'))
        result = await self.reset()
        self.assertEqual(self.trace, ['session', 'info'])
        self.assert_result(result, ok=True, phase='confirmed')
        self.assertEqual((await self.durable()).backup, (NEW_SECRET, 'official_confirmed'))


class UnreadableRecordTests(ResetCase):
    async def plant(self, value, email=EMAIL):
        async with self.factory() as db:
            db.add(SystemSetting(key=reset_key(email), value=value, description='fixture'))
            await db.commit()

    async def assert_blocked(self, email=EMAIL, server=None):
        server = server or self.server
        stored = await self.settings('totp_reset')
        result = await self.reset(email=email, server=server)
        self.assertEqual(self.trace, [], 'an unreadable record forbids every remote call')
        self.assert_result(result, ok=False, status='failed', error_code='reset_unreadable')
        self.assertEqual(await self.refused(totp_reset.status_reset, email=email), ('reset_unreadable', 409))
        with self.assertRaises(CredentialImportError):
            await self.call(totp_reset.open_reset, email)
        for function, arguments in ((totp_reset.reveal_candidate, {}), (totp_reset.abandon_reset, {'confirmed': True})):
            code, status = await self.refused(function, email=email, **arguments)
            self.assertGreaterEqual(status, 400)
        # It may hold the only copy of a live key: nothing overwrites or removes it.
        self.assertEqual(await self.settings('totp_reset'), stored)
        self.assertEqual(server.calls, [])

    async def test_garbage_under_the_record_key_blocks_the_reset(self):
        cipher = token_cipher()
        cases = [('not ciphertext', 'synthetic-garbage-not-a-record'),
                 ('ciphertext of something else', cipher.encrypt('synthetic text, not a record')),
                 ('ciphertext of a JSON list', cipher.encrypt('[1, 2, 3]')),
                 ('empty value', '')]
        for label, value in cases:
            with self.subTest(label):
                await self.restart(factors=['factor-old'])
                await self.plant(value)
                await self.assert_blocked()
                self.assertEqual(self.server.factors, ['factor-old'])

    async def test_a_record_moved_to_another_email_is_not_trusted(self):
        await self.reach('activating')
        raw = (await self.settings('totp_reset'))[reset_key(EMAIL)]
        await self.plant(raw, OTHER_EMAIL)
        other = self.new_server(email=OTHER_EMAIL, factors=['factor-theirs'], probe=lambda: self.durable(OTHER_EMAIL))
        await self.assert_blocked(OTHER_EMAIL, other)
        self.assertEqual(other.factors, ['factor-theirs'])
        # The original is still this email's readable record.
        self.assertEqual((await self.durable()).record['secret'], NEW_SECRET)

    async def test_a_key_phase_record_without_its_key_is_unreadable(self):
        await self.reach('activating')
        cipher = token_cipher()
        await self.rewrite('totp_reset:', lambda raw: cipher.encrypt(json.dumps({**json.loads(cipher.decrypt(raw)), 'secret': ''})))
        self.server = self.new_server(factors=['factor-new-1'])
        await self.assert_blocked()


class RecordAccessTests(ResetCase):
    def stamps(self, view):
        return {key: datetime.fromisoformat(value) for key, value in view.items() if key.endswith('_at')}

    async def test_status_view_follows_every_phase_and_never_shows_a_key(self):
        view = await self.view()
        self.assertEqual((view['open'], view['has_candidate'], view['exported']), (False, False, False))
        self.assertNotIn(view['phase'], (*OPEN, 'confirmed', 'abandoned'))
        self.assertTrue(isinstance(view['message'], str) and view['message'])
        for phase in OPEN:
            with self.subTest(phase):
                await self.restart()
                await self.reach(phase)
                view = await self.view()
                self.assertEqual((view['phase'], view['open'], view['has_candidate'], view['exported']),
                                 (phase, True, phase in KEYED, False))
                self.assertTrue(isinstance(view['message'], str) and view['message'])
                self.assertTrue(self.stamps(view))
                self.assertNotIn('secret', view)
                opened = await self.call(totp_reset.open_reset, EMAIL)
                self.assertEqual(opened['phase'], phase)
                self.assertEqual(opened.get('secret') or '', NEW_SECRET if phase in KEYED else '')
        await self.restart(factors=['factor-old'])
        self.assertTrue((await self.reset())['ok'])
        view = await self.view()
        self.assertEqual((view['phase'], view['open'], view['has_candidate'], view['exported']),
                         ('confirmed', False, False, False))
        self.assertTrue(self.stamps(view))
        self.assertIsNone(await self.call(totp_reset.open_reset, EMAIL))
        await self.call(totp_reset.assert_no_open_reset, EMAIL)

    async def test_candidate_export_needs_a_key_phase_and_is_marked_once(self):
        self.assertEqual(await self.refused(totp_reset.reveal_candidate, email=EMAIL), ('candidate_not_found', 404))
        await self.reach('preparing')
        self.assertEqual(await self.refused(totp_reset.reveal_candidate, email=EMAIL), ('candidate_not_found', 404))
        for phase in KEYED:
            with self.subTest(phase):
                await self.restart()
                await self.reach(phase)
                before = await self.durable()
                revealed = await self.call(totp_reset.reveal_candidate, email=EMAIL)
                self.assertEqual((revealed['email'], revealed['secret'], revealed['phase']), (EMAIL, NEW_SECRET, phase))
                first = await self.view()
                self.assertIs(first['exported'], True)
                marked = self.stamps(first)['exported_at']
                again = await self.call(totp_reset.reveal_candidate, email=EMAIL)
                self.assertEqual(again['secret'], NEW_SECRET)
                second = await self.view()
                self.assertEqual(self.stamps(second)['exported_at'], marked, 'the first export keeps its time')
                after = await self.durable()
                self.assertEqual((after.record['phase'], after.record['secret'], after.record['session_id'], after.backup),
                                 (phase, NEW_SECRET, before.record['session_id'], before.backup))
                self.assert_storage_private()
        await self.restart(factors=['factor-old'])
        self.assertTrue((await self.reset())['ok'])
        self.assertEqual(await self.refused(totp_reset.reveal_candidate, email=EMAIL), ('candidate_not_found', 404))

    async def test_abandon_requires_an_explicit_confirmation(self):
        await self.reach('prepared')
        before = await self.durable()
        for confirmed in (False, None, 1, 'true', 'yes'):
            with self.subTest(confirmed=confirmed):
                self.assertEqual(await self.refused(totp_reset.abandon_reset, email=EMAIL, confirmed=confirmed),
                                 ('confirmation_required', 400))
        self.assertEqual((await self.durable()).record, before.record)
        self.assertEqual(await self.archives(), [])

    async def test_abandon_needs_an_open_record(self):
        self.assertEqual(await self.refused(totp_reset.abandon_reset, email=EMAIL, confirmed=True), ('reset_not_open', 409))
        self.server.factors = ['factor-old']
        self.assertTrue((await self.reset())['ok'])
        self.assertEqual(await self.refused(totp_reset.abandon_reset, email=EMAIL, confirmed=True), ('reset_not_open', 409))
        final = await self.durable()
        self.assertEqual((final.record['phase'], final.backup), ('confirmed', (NEW_SECRET, 'official_confirmed')))
        await self.restart()
        await self.reach('prepared')
        await self.call(totp_reset.abandon_reset, email=EMAIL, confirmed=True)
        self.assertEqual(await self.refused(totp_reset.abandon_reset, email=EMAIL, confirmed=True), ('reset_not_open', 409))
        self.assertEqual(len(await self.archives()), 1)

    async def test_abandon_waits_for_a_browser_task_of_the_same_email(self):
        await self.reach('prepared')
        before = await self.durable()
        elsewhere = await self.add_operation('running', email=OTHER_EMAIL)
        row = await self.add_operation('success')
        for state in ('pending', 'queued', 'running', 'waiting'):
            with self.subTest(state):
                await self.set_operation(row, state)
                self.assertEqual(await self.refused(totp_reset.abandon_reset, email=EMAIL, confirmed=True),
                                 ('account_busy', 409))
                self.assertEqual((await self.durable()).record, before.record)
                self.assertEqual(await self.archives(), [])
        # Finished tasks, and tasks of another email, do not block.
        await self.set_operation(row, 'manual_required')
        self.assertIsNotNone(elsewhere)
        closed = await self.call(totp_reset.abandon_reset, email=EMAIL, confirmed=True)
        self.assertEqual((closed['phase'], closed['open'], closed['has_candidate']), ('abandoned', False, False))

    async def test_abandoning_an_unanswered_activation_requires_an_export_first(self):
        await self.reach('activating')
        before = await self.durable()
        self.assertEqual(await self.refused(totp_reset.abandon_reset, email=EMAIL, confirmed=True), ('export_required', 409))
        self.assertEqual((await self.durable()).record, before.record)
        self.assertEqual(await self.archives(), [])
        self.assertEqual((await self.call(totp_reset.reveal_candidate, email=EMAIL))['secret'], NEW_SECRET)
        closed = await self.call(totp_reset.abandon_reset, email=EMAIL, confirmed=True)
        self.assert_public(closed, what='abandon result')
        self.assertEqual((closed['phase'], closed['open'], closed['has_candidate']), ('abandoned', False, False))
        archived = await self.archives()
        self.assertEqual([item['secret'] for item in archived], [NEW_SECRET])
        self.assertEqual(archived[0]['email'], EMAIL)
        state = await self.durable()
        self.assertEqual(state.record['phase'], 'abandoned')
        self.assertNotIn(NEW_SECRET, json.dumps(state.record))
        self.assert_storage_private()

    async def test_an_abandoned_key_stays_archived_and_a_new_run_enrols_a_new_key(self):
        await self.reach('prepared')
        closed = await self.call(totp_reset.abandon_reset, email=EMAIL, confirmed=True)
        self.assert_public(closed, what='abandon result')
        self.assertEqual((closed['phase'], closed['open'], closed['has_candidate']), ('abandoned', False, False))
        view = await self.view()
        self.assertEqual((view['phase'], view['open'], view['has_candidate']), ('abandoned', False, False))
        self.assertTrue(self.stamps(view))
        archive = await self.settings('totp_reset_archive:')
        self.assertEqual(len(archive), 1)
        self.assertEqual([item['secret'] for item in await self.archives()], [NEW_SECRET])
        self.assertEqual(await self.refused(totp_reset.reveal_candidate, email=EMAIL), ('candidate_not_found', 404))
        self.assertIsNone(await self.call(totp_reset.open_reset, EMAIL))

        result = await self.reset()
        self.assertEqual(self.trace, BARE, 'the old factor is already gone; a new key is enrolled')
        self.assert_result(result, ok=True, phase='confirmed')
        self.assertEqual(self.server.enrolments[-1]['secret'], SECOND_SECRET)
        self.assertEqual((await self.durable()).backup, (SECOND_SECRET, 'official_confirmed'))
        self.assertEqual(await self.settings('totp_reset_archive:'), archive, 'archives are never deleted')

        # A second abandoned record gets its own archive row.
        self.server.plan('activate', self.server.upcoming('activate'), reply(400, BAD_CODE))
        self.assert_result(await self.reset(), ok=False, phase='prepared')
        await self.call(totp_reset.abandon_reset, email=EMAIL, confirmed=True)
        self.assertEqual(sorted(item['secret'] for item in await self.archives()), sorted((NEW_SECRET, THIRD_SECRET)))
        self.assertEqual((await self.durable()).backup, (SECOND_SECRET, 'official_confirmed'))
        self.assert_storage_private()

    async def test_abandoning_a_live_candidate_lets_the_next_run_replace_it(self):
        self.server.factors = ['factor-old']
        self.server.plan('activate', 1, lost())
        self.server.plan('info', 2, reply(500, OUTAGE))
        self.assert_result(await self.reset(), ok=False, phase='activating')
        await self.call(totp_reset.reveal_candidate, email=EMAIL)
        await self.call(totp_reset.abandon_reset, email=EMAIL, confirmed=True)
        result = await self.reset()
        self.assertEqual(self.trace, FULL)
        self.assertEqual(self.server.of('disable')[-1].data, {'factor_id': 'factor-new-1'})
        self.assert_result(result, ok=True, phase='confirmed')
        self.assertEqual((await self.durable()).backup, (SECOND_SECRET, 'official_confirmed'))
        self.assertEqual([item['secret'] for item in await self.archives()], [NEW_SECRET])

    async def test_abandon_without_a_key_creates_no_archive(self):
        await self.reach('preparing')
        closed = await self.call(totp_reset.abandon_reset, email=EMAIL, confirmed=True)
        self.assertEqual((closed['phase'], closed['open'], closed['has_candidate']), ('abandoned', False, False))
        self.assertEqual(await self.archives(), [])
        self.assertEqual((await self.durable()).record['phase'], 'abandoned')

    async def test_abandon_after_an_acknowledged_activation_keeps_the_backup(self):
        await self.reach('activated')
        closed = await self.call(totp_reset.abandon_reset, email=EMAIL, confirmed=True)
        self.assertEqual((closed['phase'], closed['open'], closed['has_candidate']), ('abandoned', False, False))
        self.assertEqual([item['secret'] for item in await self.archives()], [NEW_SECRET])
        state = await self.durable()
        self.assertEqual((state.record['phase'], state.backup), ('abandoned', (NEW_SECRET, 'official_activated')))
        self.assert_storage_private()


class BackupStoreTests(ResetCase):
    async def test_manual_backup_is_refused_while_a_reset_is_open(self):
        for phase in OPEN:
            with self.subTest(phase):
                await self.restart()
                saved = await self.call(totp_backup.save_backup, email=EMAIL, secret=OLD_SECRET, confirmed=True)
                self.assertEqual(saved['verification'], 'user_reported')
                self.assert_public(saved, what='backup result')
                await self.reach(phase)
                before = (await self.durable()).backup
                self.assertEqual(before, (NEW_SECRET, 'official_activated') if phase == 'activated'
                                 else (OLD_SECRET, 'user_reported'))
                self.assertEqual(await self.refused(totp_backup.save_backup, email=EMAIL, secret=MANUAL_SECRET,
                                                    confirmed=True), ('reset_pending', 409))
                self.assertEqual((await self.durable()).backup, before)
                self.assert_storage_private()

    async def test_manual_backup_is_allowed_when_no_reset_is_open(self):
        async def save():
            saved = await self.call(totp_backup.save_backup, email=EMAIL, secret=' on4w 45di mv2g syzn n53w 4zls fvvw k6jb ',
                                    confirmed=True)
            self.assert_result(saved, ok=True, email=EMAIL, verification='user_reported')
            self.assert_public(saved, what='backup result')
            self.assertEqual((await self.durable()).backup, (MANUAL_SECRET, 'user_reported'))
            self.assert_storage_private()

        await save()                                    # never reset
        await self.restart(factors=['factor-old'])
        self.assertTrue((await self.reset())['ok'])
        await save()                                    # after a confirmed reset
        await self.restart()
        await self.reach('prepared')
        await self.call(totp_reset.abandon_reset, email=EMAIL, confirmed=True)
        await save()                                    # after an abandoned one
        await self.restart()
        await self.reach('prepared')                    # another email's open reset does not matter
        saved = await self.call(totp_backup.save_backup, email=OTHER_EMAIL, secret=MANUAL_SECRET, confirmed=True)
        self.assertEqual(saved['verification'], 'user_reported')
        self.assertEqual((await self.durable(OTHER_EMAIL)).backup, (MANUAL_SECRET, 'user_reported'))
        self.assertIsNone((await self.durable()).backup)

    async def test_manual_backup_still_requires_confirmation_and_a_real_key(self):
        self.assertEqual((await self.refused(totp_backup.save_backup, email=EMAIL, secret=MANUAL_SECRET, confirmed=False))[0],
                         'confirmation_required')
        self.assertEqual((await self.refused(totp_backup.save_backup, email=EMAIL, secret='123456', confirmed=True))[0],
                         'invalid_totp')
        self.assertIsNone((await self.durable()).backup)

    async def test_reveal_reports_each_verification_level(self):
        self.assertEqual(await self.refused(totp_backup.reveal_backup, email=EMAIL), ('backup_not_found', 404))
        await self.call(totp_backup.save_backup, email=EMAIL, secret=OLD_SECRET, confirmed=True)
        revealed = await self.call(totp_backup.reveal_backup, email=EMAIL)
        self.assertEqual((revealed['email'], revealed['secret'], revealed['verification']),
                         (EMAIL, OLD_SECRET, 'user_reported'))
        await self.reach('activated')
        revealed = await self.call(totp_backup.reveal_backup, email=EMAIL)
        self.assertEqual((revealed['secret'], revealed['verification']), (NEW_SECRET, 'official_activated'))
        self.assertTrue((await self.reset())['ok'])
        revealed = await self.call(totp_backup.reveal_backup, email=EMAIL)
        self.assertEqual((revealed['secret'], revealed['verification']), (NEW_SECRET, 'official_confirmed'))
        self.assertTrue(datetime.fromisoformat(revealed['saved_at']))
        self.assert_storage_private()

    async def test_an_official_backup_replaces_a_user_reported_one(self):
        self.server.factors = ['factor-old']
        await self.call(totp_backup.save_backup, email=EMAIL, secret=OLD_SECRET, confirmed=True)
        await self.call(totp_backup.save_backup, email=OTHER_EMAIL, secret=FOREIGN_SECRET, confirmed=True)
        self.assertEqual(await self.call(totp_backup.stored_secret, EMAIL), OLD_SECRET)
        self.assertTrue((await self.reset())['ok'])
        self.assertEqual((await self.durable()).backup, (NEW_SECRET, 'official_confirmed'))
        self.assertEqual(await self.call(totp_backup.stored_secret, EMAIL), NEW_SECRET)
        self.assertEqual(len(await self.settings('user_totp_backup:')), 2)
        self.assertEqual((await self.durable(OTHER_EMAIL)).backup, (FOREIGN_SECRET, 'user_reported'))

    async def test_stored_secret_is_best_effort(self):
        self.assertEqual(await self.call(totp_backup.stored_secret, EMAIL), '')
        for unusable in (None, 42, '', 'not-an-email', ['owner@example.com']):
            self.assertEqual(await self.call(totp_backup.stored_secret, unusable), '')
        await self.call(totp_backup.save_backup, email=EMAIL, secret=OLD_SECRET, confirmed=True)
        self.assertEqual(await self.call(totp_backup.stored_secret, ' OWNER@example.com '), OLD_SECRET)
        self.assertEqual(await self.call(totp_backup.stored_secret, OTHER_EMAIL), '')
        cipher = token_cipher()
        good = (await self.settings('user_totp_backup:')).popitem()[1]
        document = json.loads(cipher.decrypt(good))
        pack = lambda **changes: cipher.encrypt(json.dumps({**document, **changes}))
        cases = [('not ciphertext', 'synthetic-garbage'), ('ciphertext of something else', cipher.encrypt('not a document')),
                 ('ciphertext of a JSON list', cipher.encrypt('[]')), ('another email', pack(email=OTHER_EMAIL)),
                 ('unknown verification', pack(verification='made_up')), ('a six-digit code', pack(secret='123456')),
                 ('no key', pack(secret=None)), ('empty value', '')]
        for label, value in cases:
            with self.subTest(label):
                await self.rewrite('user_totp_backup:', lambda _raw, value=value: value)
                self.assertEqual(await self.call(totp_backup.stored_secret, EMAIL), '')
                with self.assertRaises(CredentialImportError):
                    await self.call(totp_backup.reveal_backup, email=EMAIL)
        await self.rewrite('user_totp_backup:', lambda _raw: good)
        self.assertEqual(await self.call(totp_backup.stored_secret, EMAIL), OLD_SECRET)

    async def test_backup_state_never_carries_the_key(self):
        if not hasattr(totp_backup, 'backup_state'):
            self.skipTest('this build has no backup_state view')
        state = await self.call(totp_backup.backup_state, email=EMAIL)
        self.assertIs(state.get('exists'), False)
        await self.call(totp_backup.save_backup, email=EMAIL, secret=OLD_SECRET, confirmed=True)
        levels = [(await self.call(totp_backup.backup_state, email=EMAIL))]
        await self.reach('activated')
        levels.append(await self.call(totp_backup.backup_state, email=' OWNER@example.com'))
        self.assertTrue((await self.reset())['ok'])
        levels.append(await self.call(totp_backup.backup_state, email=EMAIL))
        self.assertEqual([item.get('verification') for item in levels],
                         ['user_reported', 'official_activated', 'official_confirmed'])
        for state in levels:
            self.assertIs(state.get('exists'), True)
            self.assertNotIn('secret', state)
            self.assert_public(state, what='backup state')


if __name__ == '__main__':
    unittest.main()
