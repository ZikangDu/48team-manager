"""Offline assisted-login contracts; no real browser/account or network calls."""
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import struct
import sys
import tempfile
import time
import types
import unittest
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit
from unittest.mock import AsyncMock, patch

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.main
from app.application import assisted_login as service, credential_import
from app.application.jobs.commands import command_runner
from app.application.operations import operation_store
from app.core.time import utcnow
from app.persistence.database import Base
from app.persistence.models.identity import Account
from app.persistence.models.oauth import OAuthSession
from app.persistence.models.operations import Operation
from tests.test_credential_import import record, token
# Used by the reset_totp tests at the end of this file.
from sqlalchemy import update
from app.application import totp_backup, totp_reset
from app.application.tokens import decrypt_secret, encrypt_secret
from app.core.crypto import token_cipher
from app.integrations.auth_bridge.credentials import CredentialImportError
from app.integrations.openai.mfa import MfaTransportError
from app.persistence.models.identity import Workspace
from app.persistence.models.settings import SystemSetting

EMAIL = 'member@example.com'
PASSWORD = 'fixture-private-password-never-log'
TOTP = 'JBSWY3DPEHPK3PXP'


class AssistedLoginTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_async_engine('sqlite+aiosqlite:///' + str(Path(self.tmp.name)/'fixture.db'))
        async with self.engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        self.factory = async_sessionmaker(self.engine, expire_on_commit=False)
        self.db = self.factory()
        command_runner.start(self.factory)
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.behavior = 'success'
        self.exchange = AsyncMock(return_value=record())
        self.exchange_patch = patch.object(service, '_exchange_code', self.exchange)
        self.exchange_patch.start()
        module = types.ModuleType('app.integrations.openai.browser.assisted_login')
        module.run_assisted_browser = self.driver
        self.modules = patch.dict(sys.modules, {'app.integrations.openai.browser.assisted_login': module})
        self.modules.start()

    async def asyncTearDown(self):
        self.release.set()
        await command_runner.stop()
        await service.cleanup_assisted_logins()
        self.modules.stop()
        self.exchange_patch.stop()
        credential_import.clear_previews()
        await self.db.close()
        await self.engine.dispose()
        self.tmp.cleanup()

    async def driver(self, **kwargs):
        self.entered.set()
        self.driver_proxy = kwargs['proxy']
        await kwargs['on_stage']('password', PASSWORD)
        if self.behavior == 'driver_error':
            return {'ok':False,'state':'failed','error_code':'browser_failed','message':PASSWORD}
        if self.behavior == 'hold':
            while not kwargs['cancel'].is_set():
                await asyncio.sleep(.01)
            return {'status':'cancelled'}
        if self.behavior == 'wait_release':
            await self.release.wait()
        if kwargs['action'] != 'oauth':
            return {'ok':True,'success':True,'status':'success','message':PASSWORD}
        state = parse_qs(urlsplit(kwargs['authorize_url']).query)['state'][0]
        callback = kwargs['redirect_uri']+'?'+urlencode({'code':'synthetic-code-private','state':state})
        result = await kwargs['on_callback'](callback)
        if self.behavior == 'twice':
            self.assertEqual(await kwargs['on_callback'](callback), result)
        return result

    async def start(self, **overrides):
        return await service.start_assisted_login(self.db, **{'email':EMAIL,'password':PASSWORD,'totp_secret':TOTP,**overrides})

    async def finish(self, result):
        for _ in range(300):
            if result['operation_id'] not in command_runner.running_ids():
                break
            await asyncio.sleep(.01)
        else:
            self.fail('Synthetic operation did not finish')
        await self.db.rollback()
        return await service.status_assisted_login(self.db, result['operation_id'])

    async def test_oauth_creates_one_account_without_saving_login_secrets(self):
        result = await self.start()
        self.assertTrue(result['ok'])
        status = await self.finish(result)
        self.assertEqual(status['state'],'success')
        account = await self.db.scalar(select(Account).where(Account.email==EMAIL))
        self.assertIsNotNone(account)
        self.assertIsNotNone(account.refresh_token_encrypted)
        oauth = await self.db.scalar(select(OAuthSession))
        self.assertEqual(oauth.status,'consumed')
        row = await operation_store.get_by_public_id(self.db,result['operation_id'])
        public = json.dumps([result,status,row.input_json,row.result_json,row.log_json])
        for secret in [PASSWORD,TOTP,'synthetic-code-private','rt-fixture-private']:
            self.assertNotIn(secret,public)
        self.exchange.assert_awaited_once()

    async def test_wrong_account_token_is_not_saved(self):
        self.exchange.return_value = record(email='other@example.com',access_token=token(email='other@example.com'))
        status = await self.finish(await self.start())
        self.assertEqual(status['state'],'manual_required')
        self.assertIsNone(await self.db.scalar(select(Account)))
        self.assertEqual((await self.db.scalar(select(OAuthSession))).status,'failed')

    async def test_snapshot_change_during_browser_prevents_overwrite(self):
        account = Account(email=EMAIL,local_purpose='standby',operational_state='available',auth_state='unknown')
        self.db.add(account);await self.db.commit()
        self.behavior='wait_release'
        result=await self.start();await self.entered.wait()
        async with self.factory() as other:
            changed=await other.get(Account,account.id)
            changed.credential_revision += 1
            await other.commit()
        self.release.set()
        status=await self.finish(result)
        self.assertEqual(status['state'],'manual_required')
        await self.db.refresh(account)
        self.assertIsNone(account.access_token_encrypted)

    async def test_disabled_account_is_rejected_before_browser(self):
        self.db.add(Account(email=EMAIL,local_purpose='disabled',operational_state='available',auth_state='unknown'))
        await self.db.commit()
        result=await self.start()
        self.assertEqual(result['error_code'],'account_disabled')
        self.assertFalse(self.entered.is_set())
        self.assertIsNone(await self.db.scalar(select(Operation)))

    async def test_active_authorization_blocks_duplicate_start(self):
        self.behavior='hold'
        first=await self.start();await self.entered.wait()
        second=await self.start()
        self.assertEqual(second['error_code'],'browser_busy')
        await service.cancel_assisted_login(self.db,first['operation_id'])
        status=await self.finish(first)
        self.assertEqual(status['state'],'cancelled')
        self.assertEqual((await self.db.scalar(select(OAuthSession))).status,'failed')
        self.assertIsNone(await self.db.scalar(select(Account)))
        self.assertEqual(service._controls,{})

    async def test_security_and_logout_handoffs_never_claim_verified_mutation(self):
        for action in ['security','logout_all']:
            result=await self.start(action=action)
            status=await self.finish(result)
            self.assertEqual(status['state'],'manual_required')
            self.assertFalse(status['result']['success'])
            self.assertNotIn(PASSWORD,json.dumps(status))
        self.exchange.assert_not_awaited()
        self.assertIsNone(await self.db.scalar(select(OAuthSession)))

    async def test_restart_invalidates_active_operations_even_with_future_lease(self):
        row=await operation_store.create(self.db,op_type=service.OPERATION_TYPE,email=EMAIL,
                                         lease_seconds=3600,input_payload={'action':'oauth'})
        auth={'ticket':'fixture-ticket','email':EMAIL,'state':'fixture-state','code_verifier':'fixture-verifier',
              'client_id':'fixture-client','redirect_uri':'http://localhost:1455/auth/callback',
              'expires_at':utcnow()+timedelta(minutes=10)}
        from app.application.oauth_sessions import oauth_session_store
        await oauth_session_store.persist(self.db,auth,purpose=service.OPERATION_TYPE)
        await self.db.commit()
        result=await service.recover_assisted_logins(self.db)
        self.assertEqual(result,{'recovered':1,'expired_authorizations':1})
        await self.db.refresh(row)
        self.assertEqual(row.state,'manual_required')
        self.assertEqual((await self.db.scalar(select(OAuthSession))).status,'failed')

    async def test_invalid_totp_rejected_without_secret_echo(self):
        result=await self.start(totp_secret='not-a-real-secret!')
        self.assertEqual(result['error_code'],'totp_invalid')
        self.assertNotIn('not-a-real-secret',json.dumps(result))
        self.assertFalse(self.entered.is_set())

    async def test_duplicate_callback_is_not_exchanged_or_imported_twice(self):
        self.behavior='twice'
        status=await self.finish(await self.start())
        self.assertEqual(status['state'],'success')
        self.exchange.assert_awaited_once()
        self.assertEqual(len(list(await self.db.scalars(select(Account)))),1)

    async def test_remote_refresh_owner_is_blocked_before_browser(self):
        self.db.add(Account(email=EMAIL,local_purpose='standby',operational_state='available',auth_state='unknown'))
        await self.db.commit()
        with patch.object(service,'refresh_owner_kind',AsyncMock(return_value='sub2api')):
            result=await self.start()
        self.assertEqual(result['error_code'],'remote_refresh_owned')
        self.assertFalse(self.entered.is_set())

    async def test_driver_failure_has_specific_safe_message_before_security_handoff(self):
        self.behavior='driver_error'
        status=await self.finish(await self.start(action='security'))
        self.assertEqual(status['state'],'failed')
        self.assertEqual(status['result']['error_code'],'browser_failed')
        self.assertNotIn('已交给',status['message'])
        self.assertNotIn(PASSWORD,json.dumps(status))

    async def test_proxy_remains_fixed_for_browser_and_exchange(self):
        proxy='http://proxy-user:proxy-password@127.0.0.1:18080'
        self.db.add(Account(email=EMAIL,local_purpose='standby',operational_state='available',auth_state='unknown',proxy=proxy))
        await self.db.commit()
        status=await self.finish(await self.start(totp_secret=''))
        self.assertEqual(status['state'],'success')
        self.assertEqual(self.driver_proxy,proxy)
        self.assertEqual(self.exchange.call_args.kwargs['proxy'],proxy)
        self.assertNotIn(proxy,json.dumps(status))


class PlainExchangeTests(unittest.IsolatedAsyncioTestCase):
    async def test_bounded_http_exchange_disallows_redirects_and_filters_response(self):
        calls=[]
        def respond(request):
            calls.append(request)
            return httpx.Response(200,json={**record(),'password':'upstream-private'})
        payload=await service._exchange_code(code='fixture-code',client_id='client',redirect_uri='http://localhost:1455/auth/callback',
            code_verifier='fixture-verifier',transport=httpx.MockTransport(respond))
        self.assertEqual(set(payload),{'access_token','refresh_token'})
        self.assertEqual(str(calls[0].url),service.TOKEN_ENDPOINT)
        self.assertEqual(json.loads(calls[0].content)['code_verifier'],'fixture-verifier')
        def redirect(request):
            return httpx.Response(302,headers={'location':'https://evil.example/'})
        with self.assertRaises(service.AssistedLoginError):
            await service._exchange_code(code='fixture',client_id='client',redirect_uri='fixture',code_verifier='fixture',
                                        transport=httpx.MockTransport(redirect))

    async def test_oversized_and_raw_failures_do_not_echo_secrets(self):
        with patch.object(service,'MAX_RESPONSE_BYTES',16),self.assertRaises(service.AssistedLoginError) as caught:
            await service._exchange_code(code='fixture-private',client_id='client',redirect_uri='fixture',code_verifier='private-verifier',
                transport=httpx.MockTransport(lambda _:httpx.Response(200,content=b'x'*32)))
        self.assertNotIn('fixture-private',str(caught.exception))


# ---------------------------------------------------------------------------------------------
# reset_totp: the real service, state machine and MFA client against an in-memory official API.
# ---------------------------------------------------------------------------------------------

NEW_TOTP = 'KRSXG5DSNFXGOIDBKRSXG5DSNFXGOIDB'
THIRD_TOTP = 'MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U'
BACKUP_TOTP = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
OWNER_TOTP = 'N53W4ZLSFVTGS6DUOVZGKLLLMV4S2MBR'
REMOTE_TEXT = 'REMOTE-PRIVATE-RESPONSE-TEXT'
SESSION_PATH = '/api/auth/session'
INFO_PATH = '/backend-api/accounts/mfa_info'
DISABLE_PATH = '/backend-api/accounts/mfa/user/disable_in_house'
ENROLL_PATH = '/backend-api/accounts/mfa/enroll'
ACTIVATE_PATH = '/backend-api/accounts/mfa/user/activate_enrollment'
READ_SESSION, READ_STATUS = ('GET', SESSION_PATH), ('GET', INFO_PATH)
DISABLE, ENROLL, ACTIVATE = ('POST', DISABLE_PATH), ('POST', ENROLL_PATH), ('POST', ACTIVATE_PATH)
NOT_SIGNED_IN = {'ok': False, 'state': 'manual_required', 'message': PASSWORD}


def rfc6238(key, at):
    """Independent six-digit TOTP (SHA-1, 30 s): the fake server does not trust the code under test."""
    digest = hmac.new(base64.b32decode(key + '=' * (-len(key) % 8)), struct.pack('>Q', int(at // 30)), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


class FakeMfaServer:
    """The official API as the signed-in chatgpt.com page reaches it: the five endpoints of a reset.

    It is handed to on_mfa as the transport. ``fault(path, ...)`` queues one outcome per arriving
    request: 'ok', 'lost' (applied, but the answer never came back), 'unreachable' (never arrived),
    a ``(status, text)`` answer given without acting, or an exception instance raised as it is.
    """

    def __init__(self, email=EMAIL, *, factors=('factor-old',), keys=(NEW_TOTP, THIRD_TOTP), access_token=None):
        self.access_token = access_token or token(email=email)
        self.session = {'user': {'id': 'user-fixture', 'email': email}, 'expires': '2099-01-01T00:00:00.000Z',
                        'accessToken': self.access_token}
        self.factors = list(factors)      # active TOTP factor ids, as the status endpoint lists them
        self.enabled = bool(self.factors)
        self.keys = list(keys)            # one new key per enrolment
        self.enrolments = []
        self.names_factor = True          # False: the enrolment answer carries no factor id
        self.listed_as = None             # id under which a newly activated factor shows up, if not its own
        self.calls = []                   # (method, path) in arrival order
        self.activations = []             # (session_id, code) of every activation request that was sent
        self.faults = {}
        self.hooks = {}                   # path -> coroutine function awaited once when a request arrives
        self.observer = None              # coroutine function (method, path) awaited on every arriving request

    def fault(self, path, *outcomes):
        self.faults.setdefault(path, []).extend(outcomes)

    def count(self, path):
        return sum(1 for _, seen in self.calls if seen == path)

    @property
    def mutations(self):
        return [call for call in self.calls if call[0] != 'GET']

    @property
    def codes(self):
        return [code for _, code in self.activations if isinstance(code, str) and code]

    async def request(self, method, path, *, headers, body):
        self.calls.append((method, path))
        if path == ACTIVATE_PATH:
            sent = json.loads(body)
            self.activations.append((sent.get('session_id'), sent.get('code')))
        if self.observer is not None:
            await self.observer(method, path)
        hook = self.hooks.pop(path, None)
        if hook is not None:
            await hook()
        queue = self.faults.get(path)
        outcome = queue.pop(0) if queue else 'ok'
        if outcome == 'unreachable':
            raise MfaTransportError()
        if isinstance(outcome, BaseException):
            raise outcome
        if isinstance(outcome, tuple):
            return outcome
        answer = self._serve(method, path, dict(headers), body)
        if outcome == 'lost':
            raise MfaTransportError()
        return answer

    def _serve(self, method, path, headers, body):
        if (method, path) == READ_SESSION:
            # The page's own cookie session; a bearer token has no business here.
            return (400, '{}') if 'authorization' in headers else (200, json.dumps(self.session))
        if (headers.get('authorization') != 'Bearer ' + self.access_token
                or headers.get('x-openai-target-path') != path or headers.get('x-openai-target-route') != path):
            return 401, json.dumps({'detail': {'code': 'token_invalid'}})
        if (method, path) == READ_STATUS:
            return 200, json.dumps({'mfa_enabled': self.enabled, 'factors': {'totp': [{'id': item} for item in self.factors]},
                                    'native_default_factor_id': self.factors[0] if self.factors else None})
        sent = json.loads(body) if method == 'POST' and body else {}
        if (method, path) == DISABLE:
            if sent.get('factor_id') not in self.factors:
                return 404, json.dumps({'detail': {'code': 'factor_not_found'}})
            self.factors.remove(sent['factor_id'])
            self.enabled = bool(self.factors)
            return 200, '{}'
        if (method, path) == ENROLL:
            if sent != {'factor_type': 'totp'} or len(self.enrolments) >= len(self.keys):
                return 400, json.dumps({'detail': {'code': 'enroll_refused'}})
            number = len(self.enrolments) + 1
            entry = {'session_id': f'enrol-session-{number}', 'key': self.keys[number - 1],
                     'factor_id': f'factor-new-{number}', 'active': False}
            self.enrolments.append(entry)
            return 200, json.dumps({'secret': entry['key'], 'session_id': entry['session_id'],
                                    **({'factor': {'id': entry['factor_id']}} if self.names_factor else {})})
        if (method, path) == ACTIVATE:
            entry = next((item for item in self.enrolments if item['session_id'] == sent.get('session_id')), None)
            now = time.time()
            if (entry is None or entry['active'] or sent.get('factor_type') != 'totp'
                    or sent.get('code') not in (rfc6238(entry['key'], now), rfc6238(entry['key'], now - 30))):
                return 400, json.dumps({'detail': {'code': 'activation_refused'}})
            entry['active'] = True
            self.factors.append(self.listed_as or entry['factor_id'])
            self.enabled = True
            return 200, json.dumps({'success': True})
        return 404, json.dumps({'detail': {'code': 'not_found'}})


class ResetTotpTests(unittest.IsolatedAsyncioTestCase):
    """reset_totp end to end through the real service, state machine and MFA client.

    Only the browser is replaced: ``driver`` stands in for run_assisted_browser and hands
    ``self.server`` to on_mfa as the transport of the signed-in page.
    """

    async def asyncSetUp(self):
        # Same isolated database, command runner and stubbed driver module as AssistedLoginTests;
        # the service resolves run_assisted_browser to ``driver`` of this class.
        await AssistedLoginTests.asyncSetUp(self)
        self.server = FakeMfaServer()
        self.window = 'signed_in'              # or the driver's own result when the page is never handed over
        self.proof = {'totp_accepted': False}
        self.signed_in = asyncio.Event()       # cleared by a test to hold the window before sign-in completes
        self.signed_in.set()
        self.after_mfa = None                  # coroutine function (kwargs, outcome) -> the driver's return value
        self.deadline = None                   # an Event: once set, the driver's own time limit cuts the page off
        self.handovers = 1
        self.runs, self.outcomes = [], []      # what the service gave the driver / what on_mfa answered
        clock = patch.object(totp_reset, 'totp_seconds_left', return_value=20)   # never wait for a TOTP window
        clock.start()
        self.addCleanup(clock.stop)
        self.logged = []                       # everything the process logs, with tracebacks
        capture = logging.Handler()
        capture.emit = lambda entry: self.logged.append(logging.Formatter().format(entry))
        logging.getLogger().addHandler(capture)
        self.addCleanup(logging.getLogger().removeHandler, capture)

    asyncTearDown = AssistedLoginTests.asyncTearDown
    start = AssistedLoginTests.start
    finish = AssistedLoginTests.finish

    async def driver(self, **kwargs):
        """Like run_assisted_browser: the page runs in a task of its own and only a fixed verdict comes back."""
        flow = asyncio.create_task(self.page(**kwargs))
        if self.deadline is None:
            return await flow
        await self.deadline.wait()                          # time is up while on_mfa is still in flight
        flow.cancel()
        await asyncio.gather(flow, return_exceptions=True)
        return {'ok': False, 'state': 'manual_required', 'error_code': 'browser_timeout', 'message': PASSWORD}

    async def page(self, **kwargs):
        """Like the real page loop: report stages, hand the signed-in page to on_mfa, return a fixed verdict."""
        self.entered.set()
        control = next(iter(service._controls.values()), None)
        self.runs.append({'email': kwargs['email'], 'action': kwargs['action'], 'totp_secret': kwargs['totp_secret'],
                          'uses_candidate': bool(control and control.login_uses_candidate)})
        await kwargs['on_stage']('password', PASSWORD)      # page text is untrusted and must never be stored
        await self.signed_in.wait()
        if isinstance(self.window, dict):
            return dict(self.window)
        if self.window == 'stopped_during_sign_in':
            await kwargs['cancel'].wait()
            return {'ok': False, 'state': 'cancelled', 'error_code': 'cancelled', 'message': PASSWORD}
        if kwargs['action'] != 'reset_totp':
            return dict(NOT_SIGNED_IN)
        await kwargs['on_stage']('authenticated', PASSWORD)
        outcome = None
        for _ in range(self.handovers):
            outcome = await kwargs['on_mfa'](self.server, dict(self.proof))
            self.outcomes.append(outcome)
        if self.after_mfa is not None:
            return await self.after_mfa(kwargs, outcome)
        if isinstance(outcome, dict) and (outcome.get('ok') is True or outcome.get('success') is True):
            return {'ok': True, 'state': 'success', 'message': PASSWORD}
        return {'ok': False, 'state': 'manual_required', 'error_code': 'mfa_incomplete', 'message': PASSWORD}

    async def reset(self, **overrides):
        """Start a confirmed reset; the form carries the old key unless a test says otherwise."""
        return await self.start(action='reset_totp', confirm_reset=True, **overrides)

    async def run_reset(self, **overrides):
        started = await self.reset(**overrides)
        self.assertTrue(started['ok'], started)
        return started, await self.finish(started)

    async def interrupt(self):
        """First run: the activation is applied remotely, its answer is lost and the status read fails too."""
        self.server.fault(ACTIVATE_PATH, 'lost')
        self.server.fault(INFO_PATH, 'ok', 'unreachable')
        started, status = await self.run_reset()
        self.assertEqual((status['state'], status['result'].get('phase')), ('manual_required', 'activating'), status)
        return started, status

    async def request_stop(self):
        """What the cancel endpoint does for the task that is running now, on a session of its own."""
        async with self.factory() as other:
            public_id = await other.scalar(select(Operation.public_id).where(Operation.state == 'running'))
            return await service.cancel_assisted_login(other, public_id)

    async def status(self, started):
        await self.db.rollback()
        return await service.status_assisted_login(self.db, started['operation_id'])

    async def row(self, started):
        await self.db.rollback()
        return await self.db.scalar(select(Operation).where(Operation.public_id == started['operation_id'])
                                    .execution_options(populate_existing=True))

    async def record_row(self, email=EMAIL):
        """The encrypted reset record exactly as stored, or None."""
        key = 'totp_reset:' + hashlib.sha256(email.encode()).hexdigest()
        return await self.db.scalar(select(SystemSetting.value).where(SystemSetting.key == key))

    async def backup(self, email=EMAIL):
        saved = await totp_backup.reveal_backup(self.db, email=email)
        return saved['secret'], saved['verification']

    async def assert_no_backup(self, email=EMAIL):
        with self.assertRaises(CredentialImportError) as missing:
            await totp_backup.reveal_backup(self.db, email=email)
        self.assertEqual(missing.exception.code, 'backup_not_found')

    async def assert_candidate(self, phase, key=NEW_TOTP):
        """The open record still holds the key, and its public view does not show it."""
        record = await totp_reset.load(self.db, EMAIL)
        self.assertIsNotNone(record)
        self.assertEqual((record['phase'], record['secret']), (phase, key))
        view = await totp_reset.status_reset(self.db, email=EMAIL)
        self.assertEqual((view['phase'], view['open'], view['has_candidate']), (phase, True, True))
        self.assertNotIn(key, json.dumps(view))

    async def assert_no_secret_escaped(self, *payloads, extra=()):
        """No password, key, token or activation code in the payloads, in any operation row or in the
        process log, and no password, key or token in the raw database files."""
        await self.db.rollback()
        rows = list(await self.db.scalars(select(Operation).execution_options(populate_existing=True)))
        self.assertTrue(rows)
        visible = json.dumps(payloads, ensure_ascii=False, default=str) + ''.join(
            f'\n{getattr(row, name) or ""}' for row in rows
            for name in ('input_json', 'result_json', 'log_json', 'error_message', 'error_code', 'current_step'))
        visible += '\n' + '\n'.join(self.logged)
        raw = b''.join(path.read_bytes() for path in sorted(Path(self.tmp.name).iterdir()) if path.is_file())
        self.assertIn(b'SQLite format 3', raw)
        for secret in (PASSWORD, TOTP, self.server.access_token, *self.server.keys, *extra):
            self.assertNotIn(secret, visible)
            self.assertNotIn(secret.encode(), raw)
        for code in self.server.codes:
            self.assertRegex(code, r'^\d{6}$')
            self.assertNotIn(code, visible)

    # -- confirmation, happy path, preflight ------------------------------------------------------

    async def test_reset_is_refused_without_explicit_confirmation(self):
        for label, extra in (('missing', {}), ('false', {'confirm_reset': False}), ('none', {'confirm_reset': None}),
                             ('truthy number', {'confirm_reset': 1}), ('truthy text', {'confirm_reset': 'true'})):
            with self.subTest(confirm_reset=label):
                refused = await self.start(action='reset_totp', **extra)
                self.assertFalse(refused['ok'])
                self.assertEqual(refused['error_code'], 'reset_confirmation_required')
                self.assertNotIn(PASSWORD, json.dumps(refused))
                self.assertNotIn(TOTP, json.dumps(refused))
        self.assertFalse(self.entered.is_set())
        self.assertEqual(self.runs, [])
        self.assertEqual(self.server.calls, [])
        self.assertIsNone(await self.db.scalar(select(Operation)))
        self.assertIsNone(await self.record_row())
        self.assertEqual(service._controls, {})

    async def test_reset_replaces_the_key_confirms_it_and_keeps_secrets_out_of_the_task(self):
        started, status = await self.run_reset()
        self.assertEqual((started['action'], started['email'], started['mode']), ('reset_totp', EMAIL, 'fresh'))
        self.assertEqual((status['state'], status['action'], status['mode']), ('success', 'reset_totp', 'fresh'))
        result = status['result']
        self.assertEqual((result['ok'], result['success'], result['status']), (True, True, 'success'))
        self.assertEqual((result['phase'], result['backup_saved'], result['owner_synced']), ('confirmed', True, 0))
        # The window signed in with the typed (old) key; the official sequence ran exactly once, in order.
        self.assertEqual(self.runs, [{'email': EMAIL, 'action': 'reset_totp', 'totp_secret': TOTP, 'uses_candidate': False}])
        self.assertEqual(self.server.calls, [READ_SESSION, READ_STATUS, DISABLE, ENROLL, ACTIVATE, READ_STATUS])
        self.assertEqual([session for session, _ in self.server.activations], ['enrol-session-1'])
        self.assertEqual(len(self.server.codes), 1)
        self.assertEqual(self.server.factors, ['factor-new-1'])
        self.assertIsNone(await self.db.scalar(select(OAuthSession)))   # a reset never opens an authorization
        row = await self.row(started)
        self.assertIsNone(row.error_message)
        stages = [item['stage'] for item in json.loads(row.log_json)]
        self.assertEqual([name for name in stages if name.startswith('mfa_')],
                         ['mfa_session', 'mfa_status', 'mfa_disable', 'mfa_enroll', 'mfa_activate', 'mfa_confirm'])
        self.assertNotIn(NEW_TOTP, json.dumps(self.outcomes))
        await self.assert_no_secret_escaped(started, status)
        # The new key is the email's backup at the confirmed level; the closed record keeps no key.
        self.assertEqual(await self.backup(), (NEW_TOTP, 'official_confirmed'))
        view = await totp_reset.status_reset(self.db, email=EMAIL)
        self.assertEqual((view['phase'], view['open'], view['has_candidate']), ('confirmed', False, False))
        self.assertNotIn(NEW_TOTP, json.dumps(view))
        self.assertEqual((await totp_reset.load(self.db, EMAIL))['secret'], '')
        self.assertEqual(service._controls, {})

    async def test_every_change_request_finds_its_recovery_record_already_committed(self):
        seen, polled = [], []

        async def durable(method, path):
            async with self.factory() as other:        # another connection: only committed data is visible
                record = await totp_reset.load(other, EMAIL)
                kept = await totp_backup.stored_secret(other, EMAIL)
                level = (await totp_backup.reveal_backup(other, email=EMAIL))['verification'] if kept else None
                public_id = await other.scalar(select(Operation.public_id).where(Operation.state == 'running'))
                polled.append(await service.status_assisted_login(other, public_id))   # what the page would poll now
            seen.append(((method, path), record and (record['phase'], record['secret']), (kept, level) if kept else None))

        self.server.observer = durable
        started, status = await self.run_reset()
        self.assertEqual(status['state'], 'success')
        self.assertEqual([call for call, _, _ in seen], [READ_SESSION, READ_STATUS, DISABLE, ENROLL, ACTIVATE, READ_STATUS])
        self.assertEqual(seen[2:], [
            (DISABLE, ('preparing', ''), None),             # a change may start: recorded first, no key yet
            (ENROLL, ('preparing', ''), None),
            (ACTIVATE, ('activating', NEW_TOTP), None),     # the new key was stored before any activation left
            (READ_STATUS, ('activated', NEW_TOTP), (NEW_TOTP, 'official_activated')),   # acknowledged: already the backup
        ])
        # Progress is visible while each request is in flight, and it never carries a secret.
        self.assertEqual([item['stage'] for item in polled],
                         ['mfa_session', 'mfa_status', 'mfa_disable', 'mfa_enroll', 'mfa_activate', 'mfa_confirm'])
        self.assertEqual({(item['state'], json.dumps(item['result'])) for item in polled}, {('running', '{}')})
        await self.assert_no_secret_escaped(started, status, polled)

    async def test_account_without_2fa_gets_a_key_without_any_disable_request(self):
        self.server = FakeMfaServer(factors=())
        started, status = await self.run_reset(totp_secret='')
        self.assertEqual(self.runs[-1]['totp_secret'], '')
        self.assertEqual((status['state'], status['result']['phase']), ('success', 'confirmed'))
        self.assertEqual(self.server.calls, [READ_SESSION, READ_STATUS, ENROLL, ACTIVATE, READ_STATUS])
        self.assertEqual(await self.backup(), (NEW_TOTP, 'official_confirmed'))
        await self.assert_no_secret_escaped(started, status)

    async def test_enrolment_without_a_factor_id_is_confirmed_by_the_acknowledged_activation(self):
        self.server.names_factor = False
        started, status = await self.run_reset()
        self.assertEqual((status['state'], status['result']['phase']), ('success', 'confirmed'))
        self.assertEqual(self.server.calls, [READ_SESSION, READ_STATUS, DISABLE, ENROLL, ACTIVATE, READ_STATUS])
        self.assertEqual(await self.backup(), (NEW_TOTP, 'official_confirmed'))

    async def test_remote_refresh_ownership_blocks_other_actions_but_not_a_reset(self):
        account = Account(email=EMAIL, local_purpose='standby', operational_state='available', auth_state='unknown',
                          refresh_token_encrypted=encrypt_secret('rt-remote-owned-fixture'))
        self.db.add(account)
        await self.db.commit()
        with patch.object(service, 'refresh_owner_kind', AsyncMock(return_value='sub2api')):
            for action in ('oauth', 'security', 'logout_all'):
                with self.subTest(action=action):
                    refused = await self.start(action=action)
                    self.assertEqual(refused['error_code'], 'remote_refresh_owned')
            self.assertFalse(self.entered.is_set())
            self.assertIsNone(await self.db.scalar(select(Operation)))
            started, status = await self.run_reset()
        self.assertEqual((status['state'], status['result']['phase']), ('success', 'confirmed'))
        self.assertEqual(await self.backup(), (NEW_TOTP, 'official_confirmed'))
        # The reset never touched the stored authorization that the remote side owns.
        await self.db.refresh(account)
        self.assertEqual(decrypt_secret(account.refresh_token_encrypted), 'rt-remote-owned-fixture')
        self.assertEqual(account.credential_revision, 1)
        await self.assert_no_secret_escaped(started, status, extra=('rt-remote-owned-fixture',))

    # -- identity of the signed-in window ---------------------------------------------------------

    async def test_window_signed_in_to_another_account_changes_nothing(self):
        other = 'other@example.com'
        windows = {
            'session user': FakeMfaServer(other),
            'token email claim': FakeMfaServer(access_token=token(email=other)),
            'token profile claim': FakeMfaServer(access_token=token(**{'https://api.openai.com/profile': {'email': other}})),
        }
        for label, server in windows.items():
            with self.subTest(mismatch=label):
                self.server = server
                started, status = await self.run_reset()
                self.assertEqual(status['state'], 'failed')
                self.assertEqual(status['result']['error_code'], 'session_identity_mismatch')
                # No change was sent, and the foreign token was never used against the account API.
                self.assertEqual(server.mutations, [])
                self.assertEqual(set(server.calls), {READ_SESSION})
                self.assertIsNone(await totp_reset.load(self.db, EMAIL))
                await self.assert_no_backup()
                await self.assert_no_secret_escaped(started, status)

    async def test_email_letter_case_does_not_matter_for_the_identity_check(self):
        self.server = FakeMfaServer('MEMBER@Example.COM')
        started, status = await self.run_reset(email='Member@EXAMPLE.com')
        self.assertEqual(started['email'], EMAIL)
        self.assertEqual((status['state'], status['result']['phase']), ('success', 'confirmed'))
        self.assertEqual(await self.backup(), (NEW_TOTP, 'official_confirmed'))

    async def test_foreign_session_during_a_resume_leaves_the_open_record_untouched(self):
        await self.interrupt()
        self.server.session['user']['email'] = 'other@example.com'
        calls = len(self.server.calls)
        started, status = await self.run_reset()
        self.assertEqual(status['state'], 'manual_required')
        self.assertEqual(status['result']['error_code'], 'session_identity_mismatch')
        self.assertEqual(set(self.server.calls[calls:]), {READ_SESSION})
        await self.assert_candidate('activating')
        await self.assert_no_backup()
        await self.assert_no_secret_escaped(started, status)

    # -- interrupted runs and their continuation --------------------------------------------------

    async def test_lost_activation_answer_resumes_with_the_candidate_key_and_never_enrols_twice(self):
        first, status = await self.interrupt()
        self.assertEqual(status['result']['error_code'], 'activation_unconfirmed')
        self.assertIsNot(status['result'].get('backup_saved'), True)
        await self.assert_candidate('activating')
        await self.assert_no_backup()                 # an unacknowledged key is a candidate, not the backup
        with self.assertRaises(CredentialImportError) as pending:    # and no manual copy may take its place
            await totp_backup.save_backup(self.db, email=EMAIL, secret=BACKUP_TOTP, confirmed=True)
        self.assertEqual(pending.exception.code, 'reset_pending')
        await self.assert_no_secret_escaped(first, status, extra=(BACKUP_TOTP,))

        calls = len(self.server.calls)
        second, status = await self.run_reset()       # the form still carries the OLD key
        self.assertEqual((second['mode'], status['mode']), ('resume', 'resume'))
        self.assertEqual(self.runs[-1], {'email': EMAIL, 'action': 'reset_totp', 'totp_secret': NEW_TOTP, 'uses_candidate': True})
        self.assertEqual((status['state'], status['result']['phase'], status['result']['backup_saved']), ('success', 'confirmed', True))
        # The status read showed the stored factor: nothing at all was sent to change the account again.
        self.assertEqual(self.server.calls[calls:], [READ_SESSION, READ_STATUS])
        self.assertEqual((self.server.count(DISABLE_PATH), self.server.count(ENROLL_PATH), self.server.count(ACTIVATE_PATH)), (1, 1, 1))
        # The confirmed key lives in the backup only; the closed record gives nothing away any more.
        self.assertEqual(await self.backup(), (NEW_TOTP, 'official_confirmed'))
        self.assertEqual((await totp_reset.load(self.db, EMAIL))['secret'], '')
        with self.assertRaises(CredentialImportError) as gone:
            await totp_reset.reveal_candidate(self.db, email=EMAIL)
        self.assertEqual(gone.exception.code, 'candidate_not_found')
        await self.assert_no_secret_escaped(first, second, status)

    async def test_accepted_code_from_the_candidate_key_confirms_when_the_factor_cannot_be_matched(self):
        await self.interrupt()
        self.server.factors = ['factor-listed-under-another-id']      # 2FA is on, the stored id is not listed

        self.proof = {'totp_accepted': False}
        started, status = await self.run_reset(totp_secret='')
        self.assertEqual(started['mode'], 'resume')
        self.assertEqual((self.runs[-1]['totp_secret'], self.runs[-1]['uses_candidate']), (NEW_TOTP, True))
        self.assertEqual((status['state'], status['result']['phase']), ('manual_required', 'activating'))
        await self.assert_candidate('activating')
        await self.assert_no_backup()
        # Whatever was retried used the stored enrolment; no second key was ever requested.
        self.assertEqual(self.server.count(ENROLL_PATH), 1)
        self.assertEqual({session for session, _ in self.server.activations}, {'enrol-session-1'})

        self.proof = {'totp_accepted': True}                          # the window signed in with the candidate's code
        calls = len(self.server.calls)
        started, status = await self.run_reset()
        self.assertEqual((self.runs[-1]['totp_secret'], self.runs[-1]['uses_candidate']), (NEW_TOTP, True))
        self.assertEqual((status['state'], status['result']['phase']), ('success', 'confirmed'))
        self.assertEqual(self.server.calls[calls:], [READ_SESSION, READ_STATUS])
        self.assertEqual(self.server.count(ENROLL_PATH), 1)
        self.assertEqual(await self.backup(), (NEW_TOTP, 'official_confirmed'))
        await self.assert_no_secret_escaped(started, status)

    async def test_lost_activation_answer_is_settled_by_the_status_read_of_the_same_run(self):
        self.server.fault(ACTIVATE_PATH, 'lost')
        started, status = await self.run_reset()
        self.assertEqual((status['state'], status['result']['phase'], status['result']['backup_saved']), ('success', 'confirmed', True))
        self.assertEqual(self.server.calls, [READ_SESSION, READ_STATUS, DISABLE, ENROLL, ACTIVATE, READ_STATUS])
        self.assertEqual(await self.backup(), (NEW_TOTP, 'official_confirmed'))
        await self.assert_no_secret_escaped(started, status)

    async def test_without_a_factor_id_only_the_accepted_candidate_code_settles_an_unknown_activation(self):
        self.server.names_factor = False                 # the enrolment answer gave nothing to match later
        await self.interrupt()
        calls = len(self.server.calls)
        started, status = await self.run_reset()         # 2FA is on, but nothing ties it to the stored key
        self.assertEqual(status['state'], 'manual_required')
        self.assertEqual((status['result']['error_code'], status['result']['phase']), ('factor_unmatched', 'activating'))
        self.assertEqual(self.server.calls[calls:], [READ_SESSION, READ_STATUS])
        await self.assert_candidate('activating')
        await self.assert_no_backup()

        self.proof = {'totp_accepted': True}
        calls = len(self.server.calls)
        started, status = await self.run_reset()
        self.assertEqual((status['state'], status['result']['phase']), ('success', 'confirmed'))
        self.assertEqual(self.server.calls[calls:], [READ_SESSION, READ_STATUS])
        self.assertEqual(self.server.count(ENROLL_PATH), 1)
        self.assertEqual(await self.backup(), (NEW_TOTP, 'official_confirmed'))
        await self.assert_no_secret_escaped(started, status)

    async def test_acknowledged_key_missing_from_the_listing_is_settled_by_its_accepted_sign_in_code(self):
        self.server.listed_as = 'factor-listed-under-another-id'
        first, status = await self.run_reset()
        result = status['result']
        self.assertEqual(status['state'], 'manual_required')
        self.assertEqual((result['error_code'], result['phase'], result['backup_saved']), ('confirm_mismatch', 'activated', True))
        self.assertEqual(await self.backup(), (NEW_TOTP, 'official_activated'))

        calls = len(self.server.calls)
        second, status = await self.run_reset()          # same listing, no proof: still pending, nothing is sent
        self.assertEqual(second['mode'], 'resume')
        self.assertEqual((status['state'], status['result']['phase']), ('manual_required', 'activated'))
        self.assertEqual(self.server.calls[calls:], [READ_SESSION, READ_STATUS])
        self.assertEqual(await self.backup(), (NEW_TOTP, 'official_activated'))

        self.proof = {'totp_accepted': True}
        calls = len(self.server.calls)
        third, status = await self.run_reset()
        self.assertEqual((self.runs[-1]['totp_secret'], self.runs[-1]['uses_candidate']), (NEW_TOTP, True))
        self.assertEqual((status['state'], status['result']['phase']), ('success', 'confirmed'))
        self.assertEqual(self.server.calls[calls:], [READ_SESSION, READ_STATUS])
        self.assertEqual(self.server.count(ENROLL_PATH), 1)
        self.assertEqual(await self.backup(), (NEW_TOTP, 'official_confirmed'))
        await self.assert_no_secret_escaped(first, second, third, status)

    async def test_code_accepted_from_the_typed_key_is_no_proof_in_a_fresh_run(self):
        self.proof = {'totp_accepted': True}             # true: the window signed in with the OLD key's code
        self.server.fault(ACTIVATE_PATH, 'unreachable')  # the activation never arrived; status shows no factor
        started, status = await self.run_reset()
        self.assertFalse(self.runs[-1]['uses_candidate'])
        self.assertEqual(status['state'], 'manual_required')
        self.assertEqual((status['result']['error_code'], status['result']['phase']), ('activation_unconfirmed', 'activating'))
        await self.assert_candidate('activating')
        await self.assert_no_backup()
        await self.assert_no_secret_escaped(started, status)

    async def test_code_accepted_from_the_typed_key_is_no_proof_for_a_key_that_was_never_live(self):
        self.server.fault(ACTIVATE_PATH, (400, json.dumps({'detail': {'code': 'invalid_code'}})))
        _, status = await self.run_reset()
        self.assertEqual((status['state'], status['result']['phase']), ('manual_required', 'prepared'))

        self.proof = {'totp_accepted': True}
        self.server.fault(ACTIVATE_PATH, 'unreachable')
        started, status = await self.run_reset()
        self.assertEqual(started['mode'], 'resume')
        self.assertEqual((self.runs[-1]['totp_secret'], self.runs[-1]['uses_candidate']), (TOTP, False))
        self.assertEqual(status['state'], 'manual_required')
        self.assertEqual((status['result']['error_code'], status['result']['phase']), ('activation_unconfirmed', 'activating'))
        await self.assert_candidate('activating')
        await self.assert_no_backup()
        self.assertEqual(self.server.count(ENROLL_PATH), 1)

    async def test_rejected_activation_keeps_the_key_and_is_retried_with_the_same_enrolment(self):
        attempts = []

        async def recorded(method, path):
            if path == ACTIVATE_PATH:
                async with self.factory() as other:      # what is committed when the activation arrives
                    record = await totp_reset.load(other, EMAIL)
                attempts.append(record and (record['phase'], record['secret'], record.get('attempts')))

        self.server.observer = recorded
        self.server.fault(ACTIVATE_PATH, (400, json.dumps({'detail': {'code': 'invalid_code', 'message': REMOTE_TEXT}})))
        first, status = await self.run_reset()
        result = status['result']
        self.assertEqual(status['state'], 'manual_required')
        self.assertEqual((result['error_code'], result['phase']), ('activation_rejected', 'prepared'))
        self.assertEqual((result.get('remote_status'), result.get('remote_code')), (400, 'invalid_code'))
        await self.assert_candidate('prepared')
        await self.assert_no_backup()
        await self.assert_no_secret_escaped(first, status, extra=(REMOTE_TEXT,))

        calls = len(self.server.calls)
        second, status = await self.run_reset()
        self.assertEqual(second['mode'], 'resume')
        # The stored key was never live, so the typed key still signs in and proves nothing.
        self.assertEqual((self.runs[-1]['totp_secret'], self.runs[-1]['uses_candidate']), (TOTP, False))
        self.assertEqual((status['state'], status['result']['phase']), ('success', 'confirmed'))
        self.assertEqual(self.server.calls[calls:], [READ_SESSION, READ_STATUS, ACTIVATE, READ_STATUS])
        self.assertEqual([session for session, _ in self.server.activations], ['enrol-session-1', 'enrol-session-1'])
        self.assertEqual(attempts, [('activating', NEW_TOTP, 1), ('activating', NEW_TOTP, 2)])
        self.assertEqual((self.server.count(DISABLE_PATH), self.server.count(ENROLL_PATH)), (1, 1))
        self.assertEqual(await self.backup(), (NEW_TOTP, 'official_confirmed'))
        await self.assert_no_secret_escaped(first, second, status, extra=(REMOTE_TEXT,))

    async def test_acknowledged_activation_is_backed_up_at_once_and_the_next_run_only_reads(self):
        body = json.dumps({'error': {'code': 'upstream_down', 'message': REMOTE_TEXT}})
        self.server.fault(INFO_PATH, 'ok', (503, body))                # the confirming status read fails
        first, status = await self.run_reset()
        result = status['result']
        self.assertEqual(status['state'], 'manual_required')
        self.assertEqual((result['error_code'], result['phase'], result['backup_saved']), ('confirm_pending', 'activated', True))
        self.assertEqual(await self.backup(), (NEW_TOTP, 'official_activated'))
        await self.assert_candidate('activated')
        await self.assert_no_secret_escaped(first, status, extra=(REMOTE_TEXT,))

        calls = len(self.server.calls)
        second, status = await self.run_reset()
        self.assertEqual(second['mode'], 'resume')
        self.assertEqual((self.runs[-1]['totp_secret'], self.runs[-1]['uses_candidate']), (NEW_TOTP, True))
        self.assertEqual((status['state'], status['result']['phase']), ('success', 'confirmed'))
        self.assertEqual(self.server.calls[calls:], [READ_SESSION, READ_STATUS])
        self.assertEqual(await self.backup(), (NEW_TOTP, 'official_confirmed'))
        self.assertEqual((await totp_reset.load(self.db, EMAIL))['secret'], '')
        await self.assert_no_secret_escaped(first, second, status, extra=(REMOTE_TEXT,))

    async def test_lost_disable_answer_holds_no_key_and_the_next_run_reads_the_status_first(self):
        self.server.fault(DISABLE_PATH, 'lost')        # the old factor is gone, but nobody was told
        first, status = await self.run_reset()
        self.assertEqual(status['state'], 'manual_required')
        self.assertEqual((status['result']['error_code'], status['result']['phase']), ('reset_interrupted', 'preparing'))
        self.assertEqual(self.server.calls, [READ_SESSION, READ_STATUS, DISABLE])
        view = await totp_reset.status_reset(self.db, email=EMAIL)
        self.assertEqual((view['phase'], view['open'], view['has_candidate']), ('preparing', True, False))
        await self.assert_no_backup()

        calls = len(self.server.calls)
        second, status = await self.run_reset()
        self.assertEqual((self.runs[-1]['totp_secret'], self.runs[-1]['uses_candidate']), (TOTP, False))
        self.assertEqual((status['state'], status['result']['phase']), ('success', 'confirmed'))
        # Nothing was left to disable, so the run went straight to the new key.
        self.assertEqual(self.server.calls[calls:], [READ_SESSION, READ_STATUS, ENROLL, ACTIVATE, READ_STATUS])
        self.assertEqual(await self.backup(), (NEW_TOTP, 'official_confirmed'))
        await self.assert_no_secret_escaped(first, second, status)

    async def test_refused_disable_fails_the_task_and_leaves_nothing_open(self):
        self.server.fault(DISABLE_PATH, (403, json.dumps({'detail': {'code': 'mfa_change_forbidden', 'message': REMOTE_TEXT}})))
        started, status = await self.run_reset()
        result = status['result']
        self.assertEqual(status['state'], 'failed')
        self.assertEqual(result['error_code'], 'disable_rejected')
        self.assertEqual((result.get('remote_status'), result.get('remote_code')), (403, 'mfa_change_forbidden'))
        self.assertEqual(self.server.calls, [READ_SESSION, READ_STATUS, DISABLE])
        self.assertEqual(self.server.factors, ['factor-old'])
        self.assertIsNone(await totp_reset.load(self.db, EMAIL))
        await self.assert_no_backup()
        await self.assert_no_secret_escaped(started, status, extra=(REMOTE_TEXT,))
        again, status = await self.run_reset()         # nothing is left behind: a later attempt starts over
        self.assertEqual((again['mode'], status['state'], status['result']['phase']), ('fresh', 'success', 'confirmed'))

    async def test_refused_enrolment_is_final_only_when_nothing_was_disabled_before(self):
        refusal = (400, json.dumps({'detail': {'code': 'enroll_blocked', 'message': REMOTE_TEXT}}))
        with self.subTest(account='had a factor, now disabled'):
            self.server.fault(ENROLL_PATH, refusal)
            started, status = await self.run_reset()
            self.assertEqual(status['state'], 'manual_required')
            self.assertEqual((status['result']['error_code'], status['result']['phase']), ('enroll_failed', 'preparing'))
            self.assertEqual(self.server.calls, [READ_SESSION, READ_STATUS, DISABLE, ENROLL])
            view = await totp_reset.status_reset(self.db, email=EMAIL)
            self.assertEqual((view['phase'], view['open'], view['has_candidate']), ('preparing', True, False))
            await self.assert_no_backup()
            await self.assert_no_secret_escaped(started, status, extra=(REMOTE_TEXT,))
        with self.subTest(account='had no 2FA'):
            email = 'no-2fa@example.com'
            self.server = FakeMfaServer(email, factors=())
            self.server.fault(ENROLL_PATH, refusal)
            started, status = await self.run_reset(email=email)
            self.assertEqual((status['state'], status['result']['error_code']), ('failed', 'enroll_rejected'))
            self.assertEqual(self.server.calls, [READ_SESSION, READ_STATUS, ENROLL])
            self.assertIsNone(await totp_reset.load(self.db, email))
            await self.assert_no_backup(email)
            await self.assert_no_secret_escaped(started, status, extra=(REMOTE_TEXT,))

    async def test_only_an_explicit_abandon_allows_a_second_enrolment(self):
        await self.interrupt()
        exported = await totp_reset.reveal_candidate(self.db, email=EMAIL)
        self.assertEqual(exported['secret'], NEW_TOTP)
        await totp_reset.abandon_reset(self.db, email=EMAIL, confirmed=True)

        started, status = await self.run_reset(totp_secret=NEW_TOTP)   # the user signs in with the exported key
        self.assertEqual(started['mode'], 'fresh')
        self.assertEqual((self.runs[-1]['totp_secret'], self.runs[-1]['uses_candidate']), (NEW_TOTP, False))
        self.assertEqual((status['state'], status['result']['phase']), ('success', 'confirmed'))
        self.assertEqual(self.server.count(ENROLL_PATH), 2)
        self.assertEqual(self.server.factors, ['factor-new-2'])
        self.assertEqual(await self.backup(), (THIRD_TOTP, 'official_confirmed'))
        # The new run did not drop the archived copy of the abandoned key.
        archived = list(await self.db.scalars(select(SystemSetting.key).where(SystemSetting.key.like('totp_reset_archive:%'))))
        self.assertEqual(len(archived), 1)
        await self.assert_no_secret_escaped(started, status)

    async def test_shutdown_during_activation_leaves_a_record_the_next_run_continues(self):
        reached = asyncio.Event()

        async def hang():
            reached.set()
            await asyncio.Event().wait()             # the request is in flight when the service stops

        self.server.hooks[ACTIVATE_PATH] = hang
        started = await self.reset()
        await asyncio.wait_for(reached.wait(), 3)
        await command_runner.stop()                  # service shutdown...
        command_runner.start(self.factory)           # ...and the next start
        await service.recover_assisted_logins(self.db)
        status = await self.status(started)
        self.assertEqual(status['state'], 'manual_required')
        await self.assert_candidate('activating')    # committed before the activation left
        await self.assert_no_backup()
        await self.assert_no_secret_escaped(started, status)

        second, status = await self.run_reset()
        self.assertEqual(second['mode'], 'resume')
        self.assertEqual((self.runs[-1]['totp_secret'], self.runs[-1]['uses_candidate']), (NEW_TOTP, True))
        self.assertEqual((status['state'], status['result']['phase']), ('success', 'confirmed'))
        self.assertEqual(self.server.count(ENROLL_PATH), 1)
        self.assertEqual({session for session, _ in self.server.activations}, {'enrol-session-1'})
        self.assertEqual(await self.backup(), (NEW_TOTP, 'official_confirmed'))

    async def test_window_cut_off_by_its_deadline_mid_activation_keeps_the_record_for_the_next_run(self):
        self.deadline = asyncio.Event()

        async def hang():
            self.deadline.set()                      # the activation is in flight when the driver gives up
            await asyncio.Event().wait()

        self.server.hooks[ACTIVATE_PATH] = hang
        started, status = await self.run_reset()
        self.assertEqual((status['state'], status['result']['error_code']), ('manual_required', 'browser_timeout'))
        await self.assert_candidate('activating')
        await self.assert_no_backup()
        await self.assert_no_secret_escaped(started, status)

        self.deadline = None
        second, status = await self.run_reset()
        self.assertEqual(second['mode'], 'resume')
        self.assertEqual((self.runs[-1]['totp_secret'], self.runs[-1]['uses_candidate']), (NEW_TOTP, True))
        self.assertEqual((status['state'], status['result']['phase']), ('success', 'confirmed'))
        self.assertEqual(self.server.count(ENROLL_PATH), 1)
        self.assertEqual({session for session, _ in self.server.activations}, {'enrol-session-1'})

    async def test_unexpected_page_failure_mid_reset_keeps_the_candidate_and_leaks_nothing(self):
        self.server.fault(ACTIVATE_PATH, RuntimeError(f'page crashed {NEW_TOTP} {PASSWORD}'))
        started, status = await self.run_reset()
        self.assertEqual(status['state'], 'manual_required')
        await self.assert_candidate('activating')
        await self.assert_no_backup()
        await self.assert_no_secret_escaped(started, status)
        second, status = await self.run_reset()
        self.assertEqual(second['mode'], 'resume')
        self.assertEqual((status['state'], status['result']['phase']), ('success', 'confirmed'))
        self.assertEqual(self.server.count(ENROLL_PATH), 1)

    async def test_restart_recovery_flags_the_task_for_review_and_keeps_the_record(self):
        await self.interrupt()
        before = await self.record_row()
        self.assertTrue(before)
        # A process that died mid-run leaves its task row active.
        row = await operation_store.create(self.db, op_type=service.OPERATION_TYPE, email=EMAIL, lease_seconds=3600,
                                           input_payload={'action': 'reset_totp', 'mode': 'resume'})
        await self.db.commit()
        self.assertEqual(await service.recover_assisted_logins(self.db), {'recovered': 1, 'expired_authorizations': 0})
        await self.db.refresh(row)
        self.assertEqual(row.state, 'manual_required')
        status = await service.status_assisted_login(self.db, row.public_id)
        self.assertEqual((status['state'], status['action'], status['mode']), ('manual_required', 'reset_totp', 'resume'))
        self.assertEqual(await self.record_row(), before)
        await self.assert_candidate('activating')
        started, status = await self.run_reset()      # and the record can still be continued
        self.assertEqual(started['mode'], 'resume')
        self.assertEqual((status['state'], status['result']['phase']), ('success', 'confirmed'))
        self.assertEqual(self.server.count(ENROLL_PATH), 1)

    async def test_running_reset_shows_no_result_and_blocks_abandoning_its_record(self):
        await self.interrupt()
        self.entered.clear()
        self.signed_in.clear()                         # the window is open, sign-in is not finished
        started = await self.reset()
        await asyncio.wait_for(self.entered.wait(), 3)
        live = await self.status(started)
        self.assertEqual((live['state'], live['action'], live['mode'], live['result']), ('running', 'reset_totp', 'resume', {}))
        self.assertNotIn(NEW_TOTP, json.dumps(live))
        await totp_reset.reveal_candidate(self.db, email=EMAIL)        # exported: only the running task is in the way
        with self.assertRaises(CredentialImportError) as busy:
            await totp_reset.abandon_reset(self.db, email=EMAIL, confirmed=True)
        self.assertEqual(busy.exception.code, 'account_busy')
        duplicate = await self.reset()
        self.assertFalse(duplicate['ok'])
        self.assertEqual(len(self.runs), 2)
        self.signed_in.set()
        status = await self.finish(started)
        self.assertEqual((status['state'], status['result']['phase']), ('success', 'confirmed'))
        self.assertEqual(self.server.count(ENROLL_PATH), 1)

    # -- which key signs in -----------------------------------------------------------------------

    async def test_blank_totp_field_falls_back_to_backup_then_stored_owner_2fa(self):
        self.window = dict(NOT_SIGNED_IN)              # nobody signs in, so nothing below changes the stored keys
        public = []

        async def handed(action, **overrides):
            started = await self.start(action=action, confirm_reset=action == 'reset_totp', **overrides)
            self.assertTrue(started['ok'], started)
            public.append((started, await self.finish(started)))
            self.assertEqual(self.runs[-1]['action'], action)
            return self.runs[-1]['totp_secret']

        async def expect(kept, key, **overrides):
            for action in ('oauth', 'reset_totp'):
                with self.subTest(kept=kept, action=action):
                    self.assertEqual(await handed(action, **overrides), key)

        # Somebody else's team keeps a 2FA key; it must never sign this email in.
        stranger = Account(email='stranger@example.com', local_purpose='mother', operational_state='available', auth_state='unknown')
        self.db.add(stranger)
        await self.db.flush()
        self.db.add(Workspace(name='Foreign', status='active', owner_account_id=stranger.id,
                              owner_totp_secret_encrypted=encrypt_secret(THIRD_TOTP)))
        await self.db.commit()
        await expect('nothing, email unknown', '', totp_secret='')
        account = Account(email=EMAIL, local_purpose='mother', operational_state='available', auth_state='unknown')
        self.db.add(account)
        await self.db.commit()
        await expect('nothing, account owns no team', '', totp_secret='')
        self.db.add_all([
            Workspace(name='No stored 2FA', status='active', owner_account_id=account.id),
            Workspace(name='Unreadable 2FA', status='active', owner_account_id=account.id, owner_totp_secret_encrypted='not-a-ciphertext'),
            Workspace(name='Stored 2FA', status='active', owner_account_id=account.id, owner_totp_secret_encrypted=encrypt_secret(OWNER_TOTP)),
        ])
        await self.db.commit()
        await expect('stored owner 2FA', OWNER_TOTP, totp_secret='')
        await totp_backup.save_backup(self.db, email=EMAIL, secret=BACKUP_TOTP, confirmed=True)
        await expect('backup and stored owner 2FA', BACKUP_TOTP, totp_secret='')
        await expect('backup, but a key was typed', TOTP)
        await self.db.execute(update(SystemSetting).values(value='not-a-ciphertext'))   # only the backup row exists
        await self.db.commit()
        await expect('unreadable backup', OWNER_TOTP, totp_secret='')
        self.assertEqual(self.server.calls, [])
        await self.assert_no_secret_escaped(public, extra=(BACKUP_TOTP, OWNER_TOTP))

    async def test_other_actions_use_the_candidate_key_only_when_the_field_is_blank(self):
        await self.interrupt()
        calls = len(self.server.calls)
        self.window = dict(NOT_SIGNED_IN)
        public = []
        for action in ('oauth', 'security', 'logout_all'):
            with self.subTest(action=action):
                started = await self.start(action=action, totp_secret='')
                public.append((started, await self.finish(started)))
                self.assertEqual(self.runs[-1]['totp_secret'], NEW_TOTP)
                started = await self.start(action=action)
                public.append((started, await self.finish(started)))
                self.assertEqual(self.runs[-1]['totp_secret'], TOTP)
        self.assertEqual(self.server.calls[calls:], [])
        await self.assert_candidate('activating')
        await self.assert_no_secret_escaped(public)

    async def test_reset_syncs_stored_owner_2fa_and_a_later_reset_signs_in_with_the_saved_key(self):
        owner = Account(email=EMAIL, local_purpose='mother', operational_state='available', auth_state='unknown')
        stranger = Account(email='stranger@example.com', local_purpose='mother', operational_state='available', auth_state='unknown')
        self.db.add_all([owner, stranger])
        await self.db.flush()
        owned = [Workspace(name='First', status='active', owner_account_id=owner.id, owner_totp_secret_encrypted=encrypt_secret(OWNER_TOTP)),
                 Workspace(name='Second', status='active', owner_account_id=owner.id)]
        foreign = Workspace(name='Foreign', status='active', owner_account_id=stranger.id, owner_totp_secret_encrypted=encrypt_secret(OWNER_TOTP))
        self.db.add_all([*owned, foreign])
        await self.db.commit()

        first, status = await self.run_reset(totp_secret='')
        self.assertEqual(self.runs[-1]['totp_secret'], OWNER_TOTP)      # the stored owner 2FA signed in
        self.assertEqual((status['state'], status['result']['phase'], status['result']['owner_synced']), ('success', 'confirmed', 2))
        for workspace in (*owned, foreign):
            await self.db.refresh(workspace)
        self.assertEqual([decrypt_secret(item.owner_totp_secret_encrypted) for item in owned], [NEW_TOTP, NEW_TOTP])
        self.assertEqual(decrypt_secret(foreign.owner_totp_secret_encrypted), OWNER_TOTP)

        second, status = await self.run_reset(totp_secret='')
        self.assertEqual(second['mode'], 'fresh')
        self.assertEqual((self.runs[-1]['totp_secret'], self.runs[-1]['uses_candidate']), (NEW_TOTP, False))
        self.assertEqual((status['state'], status['result']['phase'], status['result']['owner_synced']), ('success', 'confirmed', 2))
        self.assertEqual(self.server.factors, ['factor-new-2'])
        self.assertEqual(await self.backup(), (THIRD_TOTP, 'official_confirmed'))
        for workspace in (*owned, foreign):
            await self.db.refresh(workspace)
        self.assertEqual([decrypt_secret(item.owner_totp_secret_encrypted) for item in owned], [THIRD_TOTP, THIRD_TOTP])
        self.assertEqual(decrypt_secret(foreign.owner_totp_secret_encrypted), OWNER_TOTP)
        await self.assert_no_secret_escaped(first, second, status, extra=(OWNER_TOTP,))

    async def test_unreadable_reset_record_blocks_a_reset_but_not_other_actions(self):
        key = 'totp_reset:' + hashlib.sha256(EMAIL.encode()).hexdigest()
        stored = SystemSetting(key=key, value='not-a-readable-record', description='fixture')
        self.db.add(stored)
        await self.db.commit()
        for label, value in (('undecryptable', 'not-a-readable-record'), ('not a record', token_cipher().encrypt('[]'))):
            with self.subTest(record=label):
                stored.value = value
                await self.db.commit()
                refused = await self.reset()
                self.assertFalse(refused['ok'])
                self.assertEqual(refused['error_code'], 'reset_unreadable')
                self.assertNotIn(PASSWORD, json.dumps(refused))
                self.assertFalse(self.entered.is_set())
                self.assertIsNone(await self.db.scalar(select(Operation)))
                self.assertEqual(await self.record_row(), value)        # neither repaired nor removed
        started = await self.start(action='oauth')
        self.assertTrue(started['ok'], started)
        await self.finish(started)
        self.assertEqual((self.runs[-1]['action'], self.runs[-1]['totp_secret']), ('oauth', TOTP))
        self.assertEqual(await self.record_row(), value)
        self.assertEqual(self.server.calls, [])

    # -- what the window reports ------------------------------------------------------------------

    async def test_window_that_never_signs_in_reports_that_no_2fa_change_was_sent(self):
        self.window = dict(NOT_SIGNED_IN)
        started, status = await self.run_reset()
        self.assertEqual(status['state'], 'manual_required')
        self.assertEqual(status['result']['error_code'], 'browser_login_incomplete')
        generic = await self.finish(await self.start(action='oauth'))
        self.assertEqual(generic['result']['error_code'], 'browser_login_incomplete')
        # The reset has its own sentence (nothing was changed), not the generic login one.
        self.assertTrue(status['message'])
        self.assertNotEqual(status['message'], generic['message'])
        self.assertEqual(status['result']['message'], status['message'])
        self.assertEqual(self.server.calls, [])
        self.assertIsNone(await totp_reset.load(self.db, EMAIL))
        await self.assert_no_backup()
        await self.assert_no_secret_escaped(started, status, generic)

    async def test_driver_errors_keep_their_own_code(self):
        for code, state in (('browser_failed', 'failed'), ('browser_timeout', 'manual_required'), ('browser_closed', 'manual_required')):
            with self.subTest(code=code):
                self.window = {'ok': False, 'state': 'failed', 'error_code': code, 'message': PASSWORD}
                started, status = await self.run_reset()
                self.assertEqual((status['state'], status['result']['error_code']), (state, code))
                self.assertEqual(self.server.calls, [])
                self.assertIsNone(await totp_reset.load(self.db, EMAIL))
                await self.assert_no_secret_escaped(started, status)

    async def test_reset_outcome_stands_whatever_the_window_does_afterwards(self):
        stop_seen = []

        async def stopped(kwargs, outcome):
            await self.request_stop()
            stop_seen.append(kwargs['cancel'].is_set())
            return {'ok': False, 'state': 'cancelled', 'error_code': 'cancelled', 'message': PASSWORD}

        async def closed(kwargs, outcome):
            return {'ok': False, 'state': 'manual_required', 'error_code': 'browser_closed', 'message': PASSWORD}

        async def crashed(kwargs, outcome):
            raise RuntimeError(f'window crashed {PASSWORD}')

        for label, after in (('stopped', stopped), ('closed', closed), ('crashed', crashed)):
            with self.subTest(window=label):
                email = f'reset-{label}@example.com'
                self.server, self.after_mfa = FakeMfaServer(email), after
                started, status = await self.run_reset(email=email)
                self.assertEqual((status['state'], status['result']['phase']), ('success', 'confirmed'))
                self.assertEqual(await self.backup(email), (NEW_TOTP, 'official_confirmed'))
                await self.assert_no_secret_escaped(started, status)
        self.assertEqual(stop_seen, [True])           # the stop request really reached the running task

    async def test_second_handover_returns_the_first_outcome_without_running_again(self):
        self.handovers = 2
        started, status = await self.run_reset()
        self.assertEqual((status['state'], status['result']['phase']), ('success', 'confirmed'))
        self.assertEqual(len(self.outcomes), 2)
        self.assertEqual(self.outcomes[0], self.outcomes[1])
        self.assertTrue(self.outcomes[0]['ok'])
        self.assertEqual(self.server.calls, [READ_SESSION, READ_STATUS, DISABLE, ENROLL, ACTIVATE, READ_STATUS])
        self.assertNotIn(NEW_TOTP, json.dumps(self.outcomes))

    # -- stop requests ----------------------------------------------------------------------------

    async def test_stop_request_before_any_change_cancels_without_touching_the_account(self):
        for label, path in (('while the session is read', SESSION_PATH), ('while the 2FA status is read', INFO_PATH)):
            with self.subTest(stop=label):
                self.server = FakeMfaServer()
                self.server.hooks[path] = self.request_stop
                started, status = await self.run_reset()
                self.assertEqual((status['state'], status['result']['status']), ('cancelled', 'cancelled'))
                self.assertTrue(status['cancel_requested'])
                self.assertEqual(self.server.mutations, [])
                self.assertEqual(self.server.factors, ['factor-old'])
                self.assertIsNone(await totp_reset.load(self.db, EMAIL))
                await self.assert_no_secret_escaped(started, status)
        with self.subTest(stop='during sign-in'):
            self.server, self.window = FakeMfaServer(), 'stopped_during_sign_in'
            self.entered.clear()
            started = await self.reset()
            await asyncio.wait_for(self.entered.wait(), 3)
            await self.request_stop()
            status = await self.finish(started)
            self.assertEqual(status['state'], 'cancelled')
            self.assertEqual(self.server.calls, [])
            self.assertIsNone(await totp_reset.load(self.db, EMAIL))

    async def test_stop_request_on_a_resume_keeps_the_open_record(self):
        await self.interrupt()
        calls = len(self.server.calls)
        self.server.hooks[SESSION_PATH] = self.request_stop
        started, status = await self.run_reset()
        self.assertEqual((status['state'], status['result']['status']), ('cancelled', 'cancelled'))
        self.assertEqual([call for call in self.server.calls[calls:] if call[0] != 'GET'], [])
        await self.assert_candidate('activating')
        started, status = await self.run_reset()
        self.assertEqual((status['state'], status['result']['phase']), ('success', 'confirmed'))
        self.assertEqual(self.server.count(ENROLL_PATH), 1)

    async def test_stop_request_after_a_change_left_does_not_cut_the_reset_half_way(self):
        self.server.hooks[DISABLE_PATH] = self.request_stop      # the old factor is being disabled right now
        started, status = await self.run_reset()
        self.assertTrue(status['cancel_requested'])
        self.assertEqual((status['state'], status['result']['phase']), ('success', 'confirmed'))
        self.assertEqual(self.server.calls, [READ_SESSION, READ_STATUS, DISABLE, ENROLL, ACTIVATE, READ_STATUS])
        self.assertEqual(self.server.factors, ['factor-new-1'])
        self.assertEqual(await self.backup(), (NEW_TOTP, 'official_confirmed'))
        await self.assert_no_secret_escaped(started, status)

    # -- status payload ---------------------------------------------------------------------------

    async def test_status_shows_only_documented_result_fields_and_known_modes(self):
        documented = {'ok': False, 'success': False, 'status': 'manual_required', 'error_code': 'confirm_pending',
                      'message': 'fixed sentence', 'phase': 'activated', 'backup_saved': True, 'owner_synced': 2,
                      'extra_factors': 1, 'step': 'info_server_error', 'remote_status': 503, 'remote_code': 'upstream_down'}
        private = {'secret': NEW_TOTP, 'totp_secret': NEW_TOTP, 'candidate': NEW_TOTP, 'code': '123456',
                   'session_id': 'enrol-session-1', 'accessToken': self.server.access_token, 'password': PASSWORD}
        for mode, shown in (('fresh', 'fresh'), ('resume', 'resume'), ('anything-else', None), (None, None)):
            with self.subTest(mode=mode):
                row = await operation_store.create(self.db, op_type=service.OPERATION_TYPE, email=EMAIL,
                                                   input_payload={'action': 'reset_totp', **({'mode': mode} if mode else {})})
                await operation_store.finish(self.db, row, {**documented, **private})
                await self.db.commit()
                status = await service.status_assisted_login(self.db, row.public_id)
                self.assertEqual((status['state'], status['action'], status['mode']), ('manual_required', 'reset_totp', shown))
                self.assertEqual(status['result'], documented)
                for value in private.values():
                    self.assertNotIn(value, json.dumps(status))
