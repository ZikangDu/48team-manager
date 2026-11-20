"""Offline contracts for ordinary-browser assistance; no provider requests."""
import asyncio
import copy
import inspect
import json
import re
import shutil
import subprocess
import sys
import time
import traceback
import types
import unittest
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import urlencode, urlsplit

import jwt

from app.integrations.openai.browser import assisted_login as driver
from app.integrations.openai.mfa import ChatGPTMfaClient, MfaError, MfaTransportError

SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
REDIRECT = 'http://localhost:1455/auth/callback'
CALLBACK = REDIRECT + '?code=fixture-only-code&state=fixture-state'
AUTHORIZE = 'https://auth.openai.com/oauth/authorize?' + urlencode({
    'redirect_uri': REDIRECT, 'state': 'fixture-state', 'response_type': 'code',
    'client_id': 'fixture-client', 'code_challenge': 'fixture-challenge',
    'code_challenge_method': 'S256'})


class ClassificationTests(unittest.TestCase):
    def test_rfc6238_known_vector(self):
        self.assertEqual(driver.generate_totp(SECRET, timestamp=59), '287082')
        self.assertEqual(driver.generate_totp(SECRET, timestamp=1111111109), '081804')
        for value in ['', '123456', 'SECRET!']:
            with self.assertRaises(ValueError):
                driver.generate_totp(value, timestamp=59)

    def test_authenticator_is_distinct_from_email_and_ambiguous_otp(self):
        url = 'https://auth.openai.com/mfa'
        self.assertEqual(driver.classify_login_page(url, 'Enter code from your authenticator app', has_otp=True), 'totp')
        self.assertEqual(driver.classify_login_page(url, '请输入身份验证器中的验证码', has_otp=True), 'totp')
        self.assertEqual(driver.classify_login_page(url, 'Check your inbox for a code. Try authenticator instead', has_otp=True), 'email_verification')
        self.assertEqual(driver.classify_login_page('https://auth.openai.com/email-verification', 'Enter code', has_otp=True), 'email_verification')
        self.assertEqual(driver.classify_login_page(url, 'Enter code', has_otp=True), 'ambiguous_otp')

    def test_credentials_only_on_exact_https_auth_origin(self):
        for url in ['https://auth.openai.com.evil.example/login', 'http://auth.openai.com/login',
                    'https://auth.openai.com:444/login', 'https://user@auth.openai.com/login']:
            self.assertEqual(driver.classify_login_page(url, has_password=True), 'untrusted_origin')
        self.assertEqual(driver.classify_login_page('https://auth0.openai.com/login', has_password=True), 'manual_required')
        self.assertEqual(driver.classify_login_page('https://chatgpt.com/login', has_password=True), 'manual_required')
        self.assertEqual(driver.classify_login_page('https://auth.openai.com/log-in/password', has_password=True), 'password')

    def test_challenges_consent_and_registration_never_submit(self):
        url = 'https://auth.openai.com/login'
        cases = [('Verify you are human', {'has_password':True}, 'challenge'),
                 ('Too many requests', {'has_password':True}, 'rate_limited'),
                 ('Incorrect password', {'has_password':True}, 'credentials_rejected'),
                 ('Create a password', {'has_password':True}, 'account_change'),
                 ('SMS code', {'has_otp':True}, 'phone_verification')]
        for text, flags, expected in cases:
            self.assertEqual(driver.classify_login_page(url, text, **flags), expected)
        self.assertEqual(driver.classify_login_page('https://auth.openai.com/consent', 'Continue'), 'consent')
        self.assertEqual(driver.classify_login_page(url, 'Terms of service', has_email=True), 'email')
        for text in ['Wrong code', 'Incorrect authentication code', 'Invalid verification code']:
            self.assertEqual(driver.classify_login_page(url, text, has_otp=True), 'credentials_rejected')

    def test_callback_matches_exact_redirect_only(self):
        self.assertTrue(driver.matches_callback(CALLBACK, REDIRECT))
        for value in [CALLBACK.replace('localhost', '127.0.0.1'), CALLBACK.replace('1455', '1456'),
                      CALLBACK.replace('/auth/callback', '/other'), CALLBACK + '#fragment',
                      CALLBACK.replace('http://', 'http://user@')]:
            self.assertFalse(driver.matches_callback(value, REDIRECT))

    def test_proxy_fixed_and_unsupported_socks_auth_rejected(self):
        self.assertEqual(driver._proxy_options(''), None)
        self.assertEqual(driver._proxy_options('http://u:p@proxy.example:8080')['server'], 'http://proxy.example:8080')
        with self.assertRaises(ValueError):
            driver._proxy_options('socks5://u:p@proxy.example:1080')


class EmptyLocator:
    async def count(self): return 0


class FakePage:
    def __init__(self):
        self.url = 'https://auth.openai.com/login'
        self.closed = False
        self.gotos = []
    def is_closed(self): return self.closed
    def locator(self, selector): return EmptyLocator()
    def get_by_role(self, role, name): return EmptyLocator()
    def set_default_timeout(self, value): pass
    def set_default_navigation_timeout(self, value): pass
    async def goto(self, url, **kwargs): self.url = url; self.gotos.append(url)


class FormInput:
    def __init__(self, action=''):
        self.action = action
        self.fill = AsyncMock()
        self.press = AsyncMock()
    async def count(self): return 1
    def nth(self, index): return self
    async def is_visible(self): return True
    def locator(self, selector): return self
    async def get_attribute(self, name): return self.action


class DriverFlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_form_action_is_checked_before_password_is_filled(self):
        page = FakePage()
        field = FormInput('https://evil.example/collect')
        page.locator = lambda selector: field
        self.assertFalse(await driver._fill_and_submit(page, driver.PASSWORD_SELECTOR, 'fixture-private-password'))
        field.fill.assert_not_awaited()
        field.press.assert_not_awaited()
        field.action = '/log-in/password'
        self.assertTrue(await driver._fill_and_submit(page, driver.PASSWORD_SELECTOR, 'fixture-private-password'))
        field.fill.assert_awaited_once_with('fixture-private-password')
        field.press.assert_awaited_once_with('Enter')

    async def test_email_password_totp_then_callback_once_without_secret_output(self):
        page = FakePage()
        snapshots = [
            {'url':page.url, 'has_email':True},
            {'url':page.url, 'has_password':True},
            {'url':page.url, 'text':'Authenticator code', 'has_otp':True},
        ]
        captured = {}
        calls = []
        async def fill(_page, selector, value):
            calls.append((selector, value))
            if selector == driver.OTP_SELECTOR:
                captured['url'] = CALLBACK
            return True
        callback = AsyncMock(return_value={'ok':True, 'token':'not-public'})
        with patch.object(driver, '_snapshot', AsyncMock(side_effect=snapshots)), patch.object(driver, '_fill_and_submit', fill):
            result = await asyncio.wait_for(driver._drive_page(page, action='oauth', email='fixture@example.com',
                password='fixture-private-password', totp_secret=SECRET, redirect_uri=REDIRECT,
                captured=captured, on_stage=AsyncMock(), on_callback=callback), 3)
        self.assertTrue(result['ok'])
        self.assertEqual(len(calls), 3)
        self.assertRegex(calls[2][1], r'^\d{6}$')
        callback.assert_awaited_once_with(CALLBACK)
        self.assertNotIn('fixture-private-password', str(result))
        self.assertNotIn(CALLBACK, str(result))
        self.assertNotIn('not-public', str(result))

    async def test_email_otp_handoff_never_submits_or_reads_page_again(self):
        page = FakePage()
        async def stage(name, _message):
            if name == 'email_verification': page.closed = True
        snapshot = AsyncMock(return_value={'url':page.url,'text':'Check your inbox for a code','has_otp':True})
        fill = AsyncMock()
        with patch.object(driver, '_snapshot', snapshot), patch.object(driver, '_fill_and_submit', fill):
            result = await driver._drive_page(page, action='oauth', email='fixture@example.com', password='fixture',
                totp_secret=SECRET, redirect_uri=REDIRECT,captured={},on_stage=stage,on_callback=AsyncMock())
        fill.assert_not_awaited()
        snapshot.assert_awaited_once()
        self.assertEqual(result['error_code'], 'browser_closed')

    async def test_security_handoff_does_not_read_new_key_or_claim_success(self):
        page = FakePage(); page.url = 'https://chatgpt.com/'
        async def stage(name, _message):
            if name == 'awaiting_user': page.closed = True
        snapshot = AsyncMock(return_value={'url':page.url, 'logged_in':True})
        with patch.object(driver, '_snapshot', snapshot), patch.object(driver, '_open_security_settings', AsyncMock(return_value=True)):
            result = await driver._drive_page(page,action='security',email='fixture@example.com',password='fixture',
                totp_secret=SECRET,redirect_uri='',captured={},on_stage=stage,on_callback=None)
        self.assertFalse(result['ok'])
        snapshot.assert_awaited_once()

    async def test_callback_failure_does_not_echo_callback_or_response(self):
        page = FakePage()
        callback = AsyncMock(return_value={'ok':False,'message':'fixture-private-password'})
        result = await driver._drive_page(page,action='oauth',email='fixture@example.com',password='fixture',
            totp_secret=SECRET,redirect_uri=REDIRECT,captured={'url':CALLBACK},on_stage=None,on_callback=callback)
        self.assertEqual(result['error_code'], 'callback_rejected')
        self.assertNotIn('fixture-private-password',str(result))
        self.assertNotIn(CALLBACK,str(result))

    async def test_missing_authenticator_key_hands_off_without_guessing(self):
        page = FakePage()
        async def stage(name, _message):
            if name == 'manual_required': page.closed = True
        snapshot = AsyncMock(return_value={'url':page.url,'text':'Authenticator code','has_otp':True})
        fill = AsyncMock()
        with patch.object(driver, '_snapshot', snapshot), patch.object(driver, '_fill_and_submit', fill):
            result = await driver._drive_page(page, action='oauth', email='fixture@example.com', password='fixture',
                totp_secret='', redirect_uri=REDIRECT,captured={},on_stage=stage,on_callback=AsyncMock())
        fill.assert_not_awaited()
        self.assertEqual(result['error_code'], 'browser_closed')

    async def test_rejected_password_has_distinct_stage_and_no_retry(self):
        page = FakePage()
        stages = []
        async def stage(name, _message):
            stages.append(name)
            if name == 'credentials_rejected': page.closed = True
        snapshots = [ {'url':page.url,'has_password':True},
                      {'url':page.url,'has_password':True,'text':'Incorrect password'} ]
        fill = AsyncMock(return_value=True)
        with patch.object(driver, '_snapshot', AsyncMock(side_effect=snapshots)), patch.object(driver, '_fill_and_submit', fill):
            result = await driver._drive_page(page, action='oauth', email='fixture@example.com', password='fixture',
                totp_secret='', redirect_uri=REDIRECT,captured={},on_stage=stage,on_callback=AsyncMock())
        fill.assert_awaited_once()
        self.assertIn('credentials_rejected', stages)
        self.assertFalse(result['ok'])

    async def test_handoff_reasons_are_fixed_and_never_echo_page_text(self):
        fixtures = [
            ('challenge', {'text':'Verify you are human'}),
            ('email_verification', {'text':'Check your inbox','has_otp':True}),
            ('phone_verification', {'text':'SMS code','has_otp':True}),
            ('account_change', {'url':'https://auth.openai.com/reset-password','has_password':True}),
            ('consent', {'url':'https://auth.openai.com/consent','text':'Authorize access'}),
            ('untrusted_origin', {'url':'https://example.invalid/login','has_password':True}),
            ('ambiguous_otp', {'text':'Enter code','has_otp':True}),
        ]
        for expected, fixture in fixtures:
            with self.subTest(stage=expected):
                page = FakePage(); stages = []
                async def stage(name, message):
                    stages.append((name, message)); page.closed = True
                snap = {'url':page.url, **fixture}
                snap['text'] = str(snap.get('text', '')) + ' PRIVATE-FIXTURE-DO-NOT-ECHO'
                fill = AsyncMock()
                with patch.object(driver, '_snapshot', AsyncMock(return_value=snap)), patch.object(driver, '_fill_and_submit', fill):
                    await driver._drive_page(page, action='oauth', email='fixture@example.com', password='fixture',
                        totp_secret='', redirect_uri=REDIRECT,captured={},on_stage=stage,on_callback=AsyncMock())
                self.assertEqual(stages[0][0], expected)
                self.assertNotIn('PRIVATE-FIXTURE-DO-NOT-ECHO', str(stages))
                fill.assert_not_awaited()


class FakeBrowser:
    def __init__(self): self.closed = False; self.page = FakePage(); self.routes = []
    async def new_context(self): return self
    async def new_page(self): return self.page
    async def route(self, pattern, handler): self.routes.append((pattern, handler))
    async def close(self): self.closed = True


class FakePlaywright:
    def __init__(self, browser):
        self.launch = AsyncMock(return_value=browser)
        self.chromium = types.SimpleNamespace(launch=self.launch)
    async def __aenter__(self): return self
    async def __aexit__(self, *args): return False


class LifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancellation_closes_browser_without_stealth_or_storage(self):
        browser = FakeBrowser(); playwright = FakePlaywright(browser)
        cancel = asyncio.Event()
        async def drive(*args, **kwargs):
            cancel.set()
            await asyncio.Future()
        module = types.SimpleNamespace(async_playwright=lambda:playwright)
        with patch.dict(sys.modules, {'playwright.async_api':module}), patch.object(driver, '_drive_page',drive):
            result = await driver.run_assisted_browser(email='fixture@example.com',password='fixture',totp_secret=SECRET,
                authorize_url=AUTHORIZE,redirect_uri=REDIRECT,action='oauth',cancel=cancel,
                on_stage=AsyncMock(),on_callback=AsyncMock())
        self.assertEqual(result['state'], 'cancelled')
        self.assertTrue(browser.closed)
        self.assertEqual(playwright.launch.call_args.kwargs, {'headless':False,'channel':'chrome'})

    async def test_bad_authorize_origin_fails_before_browser(self):
        for authorize in [AUTHORIZE.replace('auth.openai.com','evil.example'), AUTHORIZE.replace('code&','token&')]:
            result = await driver.run_assisted_browser(email='fixture@example.com',password='fixture',totp_secret=SECRET,
                authorize_url=authorize,redirect_uri=REDIRECT,action='oauth',cancel=asyncio.Event(),
                on_stage=AsyncMock(),on_callback=AsyncMock())
            self.assertEqual(result['error_code'], 'browser_input_invalid')

    async def test_cancelled_before_start_does_not_launch(self):
        cancel = asyncio.Event();cancel.set()
        result = await driver.run_assisted_browser(email='fixture@example.com',password='fixture',totp_secret=SECRET,
            authorize_url=AUTHORIZE,redirect_uri=REDIRECT,action='oauth',cancel=cancel,on_stage=None,on_callback=AsyncMock())
        self.assertEqual(result['state'], 'cancelled')

    async def test_timeout_closes_browser_and_does_not_retry(self):
        browser = FakeBrowser(); playwright = FakePlaywright(browser)
        async def drive(*args, **kwargs): await asyncio.Future()
        module = types.SimpleNamespace(async_playwright=lambda:playwright)
        with patch.dict(sys.modules, {'playwright.async_api':module}), patch.object(driver, '_drive_page',drive):
            result = await driver.run_assisted_browser(email='fixture@example.com',password='fixture',totp_secret=SECRET,
                authorize_url=AUTHORIZE,redirect_uri=REDIRECT,action='oauth',cancel=asyncio.Event(),
                on_stage=None,on_callback=AsyncMock(),timeout_seconds=1)
        self.assertEqual(result['error_code'],'browser_timeout')
        self.assertTrue(browser.closed)
        playwright.launch.assert_awaited_once()


# ---------------------------------------------------------------------------------------------
# reset_totp: once the window is signed in, the caller's MFA routine talks to the official API
# through the page itself. Everything below is offline: the page, its cookies and the "API" are
# stand-ins, and every key, code and token is synthetic.
# ---------------------------------------------------------------------------------------------

EMAIL = 'member@example.com'
PASSWORD = 'fixture-private-password-never-log'
NEW_SECRET = 'KRSXG5DSNFXGOIDBKRSXG5DSNFXGOIDB'
DEVICE = 'fixture-device-0001'
CHATGPT = 'https://chatgpt.com/'
LOGIN = 'https://auth.openai.com/log-in'
SESSION_PATH = '/api/auth/session'
INFO_PATH = '/backend-api/accounts/mfa_info'
DISABLE_PATH = '/backend-api/accounts/mfa/user/disable_in_house'
ENROLL_PATH = '/backend-api/accounts/mfa/enroll'
ACTIVATE_PATH = '/backend-api/accounts/mfa/user/activate_enrollment'
TOKEN = jwt.encode({'email': EMAIL, 'https://api.openai.com/profile': {'email': EMAIL}},
                   'synthetic-fixture-not-a-real-key', algorithm='HS256')
# What the driver sees on the official sign-in pages (fields of _snapshot).
EMAIL_FORM = {'has_email': True}
PASSWORD_FORM = {'has_password': True}
TOTP_FORM = {'text': 'Enter the code from your authenticator app', 'has_otp': True}
EMAIL_CODE_FORM = {'text': 'Check your inbox for a code', 'has_otp': True}


class FastAsyncio:
    """Stands in for the driver's ``asyncio`` name so that its own waiting costs no wall time.

    ``sleep`` only yields to the loop; ``wait`` and ``wait_for`` keep their meaning with the
    timeout multiplied by ``scale``. Everything else is the real module. ``timed_out`` is set
    whenever a ``wait`` ran out of time, so a fake flow can continue "after the deadline"
    without racing a timer.
    """

    def __init__(self, scale=1.0):
        self.scale = scale
        self.timeouts = []
        self.timed_out = asyncio.Event()

    def __getattr__(self, name):
        return getattr(asyncio, name)

    def _scaled(self, timeout):
        self.timeouts.append(timeout)
        return None if timeout is None else timeout * self.scale

    async def sleep(self, delay, result=None):
        await asyncio.sleep(0)
        return result

    async def wait_for(self, awaitable, timeout):
        return await asyncio.wait_for(awaitable, self._scaled(timeout))

    async def wait(self, tasks, *, timeout=None, return_when=asyncio.ALL_COMPLETED):
        done, pending = await asyncio.wait(tasks, timeout=self._scaled(timeout), return_when=return_when)
        if not done:
            self.timed_out.set()
        return done, pending


class FakeClock:
    """Stands in for the driver's ``time`` name: monotonic() moves only when a test moves it."""

    def __init__(self, now=1000.0):
        self.now = now

    def monotonic(self):
        return self.now

    def __getattr__(self, name):
        return getattr(time, name)


class CookieJar:
    """What the reset path uses of ``page.context``: cookies() only."""

    def __init__(self, cookies=(), error=None):
        self.items = [dict(cookie) for cookie in cookies]
        self.error = error
        self.reads = 0

    async def cookies(self, urls=None):
        self.reads += 1
        if self.error is not None:
            raise self.error
        return [dict(cookie) for cookie in self.items]


EMPTY_JSON = object()  # default page answer: HTTP 200 with the body "{}"


class SignedInPage(FakePage):
    """FakePage plus what the reset path needs: evaluate() and context.cookies().

    ``session`` is the probe script's answer and ``respond`` the fetch script's; either may be a
    value, an exception to raise, or a callable producing one. Nothing here reaches a network.
    """

    def __init__(self, url=CHATGPT, *, session=True, respond=EMPTY_JSON, cookies=(), cookie_error=None,
                 close_after=None, lands_on=None):
        super().__init__()
        self.url = url
        self.session = session
        self.respond = {'status': 200, 'text': '{}'} if respond is EMPTY_JSON else respond
        self.context = CookieJar(cookies, cookie_error)
        self.close_after = close_after
        self.lands_on = lands_on
        self.polls = 0
        self.evaluations = []

    def is_closed(self):
        self.polls += 1
        return self.closed or (self.close_after is not None and self.polls > self.close_after)

    async def goto(self, url, **kwargs):
        await super().goto(url, **kwargs)
        if self.lands_on:
            self.url = self.lands_on

    async def evaluate(self, script, argument=None):
        # The driver wipes the header dict it handed over, so keep an independent copy.
        self.evaluations.append((script, copy.deepcopy(argument)))
        if script == driver._PROBE_SCRIPT:
            outcome = self.session() if callable(self.session) else self.session
        elif script == driver._FETCH_SCRIPT:
            outcome = self.respond(argument) if callable(self.respond) else self.respond
        else:
            raise AssertionError('the driver evaluated a script these tests do not know')
        if inspect.isawaitable(outcome):
            outcome = await outcome
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    @property
    def probes(self):
        return [argument for script, argument in self.evaluations if script == driver._PROBE_SCRIPT]

    @property
    def fetches(self):
        return [argument for script, argument in self.evaluations if script == driver._FETCH_SCRIPT]


def snapshots(page, steps):
    """Stand-in for _snapshot: what the driver sees each time it looks; the last step repeats.

    A step is a dict of snapshot fields or a callable(page) returning one. Every look gets a
    fresh dict because the driver wipes a snapshot as soon as it has classified it.
    """
    async def snapshot(_page):
        step = steps[min(snapshot.count, len(steps) - 1)]
        snapshot.count += 1
        fields = step(page) if callable(step) else step
        return {'url': page.url, **fields}
    snapshot.count = 0
    return snapshot


def script_parameters(script):
    """Names a script destructures from its single argument; None if it is written differently."""
    found = re.match(r'\s*async\s*\(\s*\{([^}]*)\}\s*\)\s*=>', script)
    if not found:
        return None
    return {name.split('=')[0].split(':')[0].strip() for name in found.group(1).split(',') if name.strip()}


def single_call(expression, name):
    """True when ``expression`` is exactly one call ``name(...)`` and nothing after it."""
    if not expression.startswith(name + '(') or not expression.endswith(')'):
        return False
    depth = 0
    for index, char in enumerate(expression):
        if char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
            if depth == 0:
                return index == len(expression) - 1
    return False


class NoLeaks:
    def assert_nothing_private(self, *exposed, also=()):
        rendered = repr(exposed)
        for value in (PASSWORD, SECRET, NEW_SECRET, TOKEN, *also):
            self.assertNotIn(value, rendered)


class SessionProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_only_an_exact_true_from_the_probe_script_counts_as_a_session(self):
        page = FakePage()
        page.evaluate = AsyncMock(return_value=True)
        self.assertIs(await driver._probe_session(page), True)
        page.evaluate.assert_awaited_once()
        script, *rest = page.evaluate.await_args.args
        self.assertEqual(script, driver._PROBE_SCRIPT)
        (limit,) = [*rest, *page.evaluate.await_args.kwargs.values()]
        self.assertNotIsInstance(limit, bool)
        self.assertGreater(limit, 0)  # the script's own time limit; without one it would abort at once

        for answer in (False, None, 1, 'true', TOKEN, {'accessToken': TOKEN}, [True]):
            with self.subTest(answer=type(answer).__name__):
                page.evaluate = AsyncMock(return_value=answer)
                self.assertIs(await driver._probe_session(page), False)
                self.assertEqual(page.evaluate.await_args.args[0], driver._PROBE_SCRIPT)
        for failure in (RuntimeError('Execution context was destroyed'), asyncio.TimeoutError(), KeyError('x')):
            with self.subTest(failure=type(failure).__name__):
                page.evaluate = AsyncMock(side_effect=failure)
                self.assertIs(await driver._probe_session(page), False)
        page.evaluate = Mock(side_effect=RuntimeError('page is gone'))  # fails before anything is awaited
        self.assertIs(await driver._probe_session(page), False)

    async def test_probe_that_never_answers_is_not_a_session(self):
        async def never(*_args, **_kwargs):
            await asyncio.Future()
        page = FakePage()
        page.evaluate = never
        with patch.object(driver, 'asyncio', FastAsyncio(scale=0.002)):
            self.assertIs(await asyncio.wait_for(driver._probe_session(page), 3), False)


class ResetDriveTests(NoLeaks, unittest.IsolatedAsyncioTestCase):
    """_drive_page(action='reset_totp'): when the reset starts and what it is told about the login."""

    def setUp(self):
        self.stages = []
        fast = patch.object(driver, 'asyncio', FastAsyncio())
        fast.start()
        self.addCleanup(fast.stop)

    async def stage(self, name, message):
        self.stages.append((name, message))

    async def drive(self, page, on_mfa, *, action='reset_totp', totp_secret=SECRET, guard=None, on_stage=None):
        return await asyncio.wait_for(driver._drive_page(
            page, action=action, email=EMAIL, password=PASSWORD, totp_secret=totp_secret, redirect_uri='',
            captured={}, on_stage=on_stage or self.stage, on_callback=None, on_mfa=on_mfa, guard=guard), 3)

    async def test_signed_in_chatgpt_page_starts_the_reset_once_with_a_page_transport(self):
        page = SignedInPage(CHATGPT)
        seen = []

        async def reset(transport, proof):
            seen.append((dict(proof), len(page.fetches)))
            return {'ok': True, 'success': True, 'candidate': NEW_SECRET, 'message': PASSWORD}

        on_mfa = AsyncMock(side_effect=reset)
        result = await self.drive(page, on_mfa)

        on_mfa.assert_awaited_once()
        self.assertEqual(on_mfa.await_args.kwargs, {})
        transport, proof = on_mfa.await_args.args
        self.assertIsInstance(transport, driver.PageFetchTransport)
        self.assertEqual(proof, {'totp_accepted': False})
        self.assertIs(proof['totp_accepted'], False)
        # Before the routine ran, the driver asked the page for nothing but whether a session exists.
        self.assertEqual(seen, [({'totp_accepted': False}, 0)])
        self.assertEqual(len(page.probes), 1)
        self.assertIs(result['ok'], True)
        self.assertFalse(result.get('error_code'))
        # The transport belongs to this very window.
        await transport.request('GET', SESSION_PATH, headers={'accept': 'application/json'}, body=None)
        self.assertEqual([call['path'] for call in page.fetches], [SESSION_PATH])
        # Only a fixed result comes back: nothing of what the routine returned, nothing of the login.
        self.assert_nothing_private(result, self.stages)

    async def test_anything_but_an_explicit_ok_from_the_reset_is_reported_as_incomplete(self):
        private = 'fixture-private-routine-detail'
        outcomes = [None, {}, 'ok', ['ok'], {'ok': 'true'}, {'ok': 1},
                    {'ok': False, 'error_code': 'activation_rejected', 'message': private, 'candidate': NEW_SECRET}]
        for outcome in outcomes:
            with self.subTest(outcome=outcome):
                on_mfa = AsyncMock(return_value=outcome)
                result = await self.drive(SignedInPage(CHATGPT), on_mfa)
                on_mfa.assert_awaited_once()
                self.assertIs(result['ok'], False)
                self.assertEqual(result['error_code'], 'mfa_incomplete')
                self.assert_nothing_private(result, self.stages, also=(private,))

    async def test_session_is_not_probed_outside_the_signed_in_chatgpt_app(self):
        elsewhere = [LOGIN, 'https://auth.openai.com/mfa/totp', 'https://auth0.openai.com/u/login',
                     'https://chatgpt.com/auth/login', 'https://chatgpt.com/api/auth/callback/openai?code=fixture',
                     'https://chatgpt.com.evil.example/', 'http://chatgpt.com/', 'https://chatgpt.com:8443/']
        for url in elsewhere:
            with self.subTest(url=url):
                # A session "exists", so any probe would start the reset; the window is closed after 8 looks.
                page = SignedInPage(url, close_after=8)
                on_mfa = AsyncMock(return_value={'ok': True})
                with patch.object(driver, '_snapshot', snapshots(page, [{}])):
                    result = await self.drive(page, on_mfa)
                self.assertEqual(page.evaluations, [])
                on_mfa.assert_not_awaited()
                self.assertEqual(result['error_code'], 'browser_closed')

    async def test_session_probe_is_repeated_no_faster_than_its_interval(self):
        clock = FakeClock()
        probed_at = []

        def session():  # signed out at first; the third probe finds the session
            probed_at.append(clock.now)
            return len(probed_at) >= 3

        def one_second_later(_page):
            clock.now += 1.0
            return {}

        page = SignedInPage(CHATGPT, session=session)
        looks = snapshots(page, [one_second_later])
        on_mfa = AsyncMock(return_value={'ok': True})
        with patch.object(driver, 'time', clock), patch.object(driver, '_snapshot', looks):
            result = await self.drive(page, on_mfa)
        self.assertIs(result['ok'], True)
        on_mfa.assert_awaited_once()
        self.assertEqual(len(probed_at), 3)
        for earlier, later in zip(probed_at, probed_at[1:]):
            self.assertGreaterEqual(later - earlier, driver.SESSION_PROBE_SECONDS)
        self.assertGreater(looks.count, len(probed_at))  # it looked at the page more often than it probed

    async def test_guard_is_critical_only_while_the_reset_routine_runs(self):
        guard = {'critical': False}
        seen = {}

        def session():
            seen['while_probing'] = guard['critical']
            return True

        async def reset(transport, proof):
            seen['during'] = guard['critical']
            return {'ok': True}

        result = await self.drive(SignedInPage(CHATGPT, session=session), reset, guard=guard)
        self.assertIs(result['ok'], True)
        self.assertEqual(seen, {'while_probing': False, 'during': True})
        self.assertIs(guard['critical'], False)

    async def test_guard_is_released_when_the_reset_routine_raises(self):
        guard = {'critical': False}
        seen = []

        async def reset(transport, proof):
            seen.append(guard['critical'])
            raise RuntimeError('fixture failure')

        try:
            result = await self.drive(SignedInPage(CHATGPT), reset, guard=guard)
        except RuntimeError:
            result = None
        self.assertEqual(seen, [True])
        self.assertIs(guard['critical'], False)
        if result is not None:  # however the failure surfaces, it is never a success
            self.assertIsNot(result.get('ok'), True)

    async def test_guard_is_released_when_the_reset_routine_is_cancelled(self):
        guard = {'critical': False}
        entered = asyncio.Event()
        seen = []

        async def reset(transport, proof):
            seen.append(guard['critical'])
            entered.set()
            await asyncio.Future()

        task = asyncio.ensure_future(self.drive(SignedInPage(CHATGPT), reset, guard=guard))
        await asyncio.wait_for(entered.wait(), 3)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(seen, [True])
        self.assertIs(guard['critical'], False)

    async def test_code_typed_by_the_driver_and_accepted_at_once_counts_as_login_proof(self):
        page = SignedInPage(LOGIN)
        typed = []

        async def fill(_page, selector, value):
            typed.append({'selector': selector, 'value': value, 'url': page.url, 'evaluated': len(page.evaluations)})
            if selector == driver.OTP_SELECTOR:
                page.url = CHATGPT  # the official site accepts the code and moves on
            return True

        on_mfa = AsyncMock(return_value={'ok': True})
        before = time.time()
        with patch.object(driver, '_snapshot', snapshots(page, [EMAIL_FORM, PASSWORD_FORM, TOTP_FORM])), \
                patch.object(driver, '_fill_and_submit', fill):
            result = await self.drive(page, on_mfa)
        after = time.time()

        on_mfa.assert_awaited_once()
        self.assertEqual(on_mfa.await_args.args[1], {'totp_accepted': True})
        self.assertIs(result['ok'], True)
        self.assertEqual([entry['selector'] for entry in typed],
                         [driver.EMAIL_SELECTOR, driver.PASSWORD_SELECTOR, driver.OTP_SELECTOR])
        self.assertEqual([entry['value'] for entry in typed[:2]], [EMAIL, PASSWORD])
        code = typed[2]['value']
        self.assertIn(code, {driver.generate_totp(SECRET, timestamp=before), driver.generate_totp(SECRET, timestamp=after)})
        for entry in typed:  # credentials only on the sign-in origin, and no script ran there
            self.assertTrue(entry['url'].startswith('https://auth.openai.com/'))
            self.assertEqual(entry['evaluated'], 0)
        self.assert_nothing_private(result, self.stages, on_mfa.await_args.args[1], also=(code,))

    async def test_any_takeover_by_the_user_withdraws_the_login_proof(self):
        email, password, otp = driver.EMAIL_SELECTOR, driver.PASSWORD_SELECTOR, driver.OTP_SELECTOR
        cases = [
            ('email code asked before the login completed', [EMAIL_FORM, PASSWORD_FORM, EMAIL_CODE_FORM],
             'email_verification', [email, password], {}),
            ('email code asked after the authenticator code', [TOTP_FORM, EMAIL_CODE_FORM],
             'email_verification', [otp], {}),
            ('authenticator code refused', [TOTP_FORM, {'text': 'Incorrect code', 'has_otp': True}],
             'credentials_rejected', [otp], {}),
            ('security check after the authenticator code', [TOTP_FORM, {'text': 'Verify you are human'}],
             'challenge', [otp], {}),
            ('no key to type', [TOTP_FORM], 'manual_required', [], {'totp_secret': ''}),
            ('code form not as expected', [TOTP_FORM], 'manual_required', [otp], {'refused': otp}),
        ]
        for label, steps, handoff, expected_typing, options in cases:
            with self.subTest(label):
                page = SignedInPage(LOGIN)
                typed, stages = [], []

                async def fill(_page, selector, value):
                    typed.append(selector)
                    return selector != options.get('refused')

                async def stage(name, message):
                    stages.append(name)
                    if name == handoff:
                        page.url = CHATGPT  # the user finishes the login by hand

                on_mfa = AsyncMock(return_value={'ok': True})
                with patch.object(driver, '_snapshot', snapshots(page, steps)), \
                        patch.object(driver, '_fill_and_submit', fill):
                    result = await self.drive(page, on_mfa, totp_secret=options.get('totp_secret', SECRET),
                                              on_stage=stage)
                self.assertIn(handoff, stages)
                self.assertEqual(typed, expected_typing)
                on_mfa.assert_awaited_once()
                self.assertEqual(on_mfa.await_args.args[1], {'totp_accepted': False})
                self.assertIs(result['ok'], True)

    async def test_code_form_still_shown_after_four_seconds_withdraws_the_login_proof(self):
        for delay, accepted in ((3.5, True), (4.5, False)):
            with self.subTest(seconds_on_the_code_form=delay):
                clock = FakeClock()
                page = SignedInPage('https://auth.openai.com/mfa/totp')

                def second_look(page):
                    clock.now += delay
                    still_asking = {'url': page.url, **TOTP_FORM}
                    page.url = CHATGPT  # ...only after this look does the form go away
                    return still_asking

                on_mfa = AsyncMock(return_value={'ok': True})
                fill = AsyncMock(return_value=True)
                with patch.object(driver, 'time', clock), patch.object(driver, '_fill_and_submit', fill), \
                        patch.object(driver, '_snapshot', snapshots(page, [TOTP_FORM, second_look])):
                    result = await self.drive(page, on_mfa)
                fill.assert_awaited_once()  # the code is never typed a second time
                on_mfa.assert_awaited_once()
                self.assertEqual(on_mfa.await_args.args[1], {'totp_accepted': accepted})
                self.assertIs(result['ok'], True)

    async def test_page_classified_as_signed_in_starts_the_reset_without_the_security_handoff(self):
        page = SignedInPage(CHATGPT, session=False)  # the probe keeps saying "no session"
        on_mfa = AsyncMock(return_value={'ok': True})
        opener = AsyncMock(return_value=True)
        with patch.object(driver, '_snapshot', snapshots(page, [{'logged_in': True}])), \
                patch.object(driver, '_open_security_settings', opener):
            result = await self.drive(page, on_mfa)
        on_mfa.assert_awaited_once()
        transport, proof = on_mfa.await_args.args
        self.assertIsInstance(transport, driver.PageFetchTransport)
        self.assertEqual(proof, {'totp_accepted': False})
        opener.assert_not_awaited()
        self.assertNotIn('awaiting_user', [name for name, _ in self.stages])
        self.assertIs(result['ok'], True)

    async def test_login_finished_by_the_user_is_recognised_without_reading_the_page_again(self):
        page = SignedInPage(LOGIN, session=False)

        async def stage(name, message):
            self.stages.append((name, message))
            if name == 'challenge':  # the user solves it; the signed-in app shows its profile control
                page.url = CHATGPT
                page.locator = lambda selector: FormInput() if selector == driver.PROFILE_SELECTOR else EmptyLocator()

        looks = snapshots(page, [{'text': 'Verify you are human'}])
        on_mfa = AsyncMock(return_value={'ok': True})
        opener = AsyncMock(return_value=True)
        with patch.object(driver, '_snapshot', looks), patch.object(driver, '_open_security_settings', opener):
            result = await self.drive(page, on_mfa, on_stage=stage)
        on_mfa.assert_awaited_once()
        self.assertEqual(on_mfa.await_args.args[1], {'totp_accepted': False})
        opener.assert_not_awaited()
        self.assertEqual(looks.count, 1)
        self.assertIs(result['ok'], True)

    async def test_security_and_logout_actions_keep_their_handoff_and_never_start_a_reset(self):
        for action in ('security', 'logout_all'):
            with self.subTest(action=action):
                page = SignedInPage(CHATGPT)  # a session exists and a reset routine is offered...
                stages = []

                async def stage(name, message):
                    stages.append(name)
                    if name == 'awaiting_user':
                        page.closed = True

                on_mfa = AsyncMock(return_value={'ok': True})
                opener = AsyncMock(return_value=True)
                with patch.object(driver, '_snapshot', snapshots(page, [{'logged_in': True}])), \
                        patch.object(driver, '_open_security_settings', opener):
                    result = await self.drive(page, on_mfa, action=action, on_stage=stage)
                on_mfa.assert_not_awaited()  # ...but only reset_totp may use it
                self.assertEqual(page.evaluations, [])
                opener.assert_awaited_once()
                self.assertIn('awaiting_user', stages)
                self.assertIsNot(result.get('ok'), True)


class PageFetchTransportTests(NoLeaks, unittest.IsolatedAsyncioTestCase):
    async def test_only_get_and_post_of_absolute_paths_on_the_chatgpt_origin_reach_the_page(self):
        refused = [(method, INFO_PATH, CHATGPT)
                   for method in ('PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'get', 'post', '', None)]
        refused += [('GET', path, CHATGPT)
                    for path in ('backend-api/accounts/mfa_info', '', 'https://chatgpt.com' + INFO_PATH,
                                 '//evil.example' + INFO_PATH, '//chatgpt.com' + INFO_PATH, None, 7)]
        refused += [('POST', '//evil.example' + ENROLL_PATH, CHATGPT)]
        refused += [('GET', INFO_PATH, url)
                    for url in (LOGIN, 'https://auth0.openai.com/u/login', 'http://chatgpt.com/',
                                'https://chatgpt.com.evil.example/', 'https://evil.example/?next=https://chatgpt.com/',
                                'https://chatgpt.com:8443/', 'https://user@chatgpt.com/', 'https://chat.openai.com/',
                                'about:blank', 'chrome-error://chromewebdata/', '')]
        for method, path, url in refused:
            with self.subTest(method=method, path=path, url=url):
                page = SignedInPage(url)
                with self.assertRaises(MfaTransportError):
                    await driver.PageFetchTransport(page).request(
                        method, path, headers={'authorization': 'Bearer ' + TOKEN}, body=None)
                self.assertEqual(page.evaluations, [])

        # The five requests of the protocol are served as they are, from any page of the signed-in app.
        served = [('GET', SESSION_PATH, CHATGPT), ('GET', INFO_PATH, CHATGPT), ('POST', DISABLE_PATH, CHATGPT),
                  ('POST', ENROLL_PATH, CHATGPT), ('POST', ACTIVATE_PATH, CHATGPT),
                  ('GET', INFO_PATH, 'https://chatgpt.com/c/fixture?model=x#top')]
        for method, path, url in served:
            with self.subTest(served=method, path=path, url=url):
                page = SignedInPage(url)
                await driver.PageFetchTransport(page).request(method, path, headers={}, body=None)
                self.assertEqual([(call['method'], call['path']) for call in page.fetches], [(method, path)])

    async def test_paths_a_browser_would_resolve_to_another_origin_never_reach_the_page(self):
        # fetch() parses its target like any URL: a backslash counts as a slash, and tabs and line
        # breaks are dropped. Each of these would therefore leave chatgpt.com, bearer header included.
        for path in ('/\\evil.example' + INFO_PATH, '/\t/evil.example' + INFO_PATH,
                     '/\n/evil.example' + INFO_PATH, '/\r/evil.example' + INFO_PATH):
            with self.subTest(path=path):
                page = SignedInPage(CHATGPT)
                with self.assertRaises(MfaTransportError):
                    await driver.PageFetchTransport(page).request(
                        'GET', path, headers={'authorization': 'Bearer ' + TOKEN}, body=None)
                self.assertEqual(page.evaluations, [])

    async def test_request_reaches_the_page_with_method_path_body_headers_and_timeout(self):
        page = SignedInPage(CHATGPT, respond={'status': 200, 'text': '{"ok":true}'},
                            cookies=[{'name': 'oai-did', 'value': DEVICE, 'domain': 'chatgpt.com', 'path': '/'}])
        transport = driver.PageFetchTransport(page, timeout_seconds=2.5)
        headers = {'accept': '*/*', 'authorization': 'Bearer ' + TOKEN, 'content-type': 'application/json',
                   'x-openai-target-path': ENROLL_PATH, 'x-openai-target-route': ENROLL_PATH}
        body = '{"factor_type":"totp"}'
        self.assertEqual(await transport.request('POST', ENROLL_PATH, headers=dict(headers), body=body),
                         (200, '{"ok":true}'))
        self.assertEqual(await transport.request('GET', INFO_PATH, headers={'accept': '*/*'}, body=None),
                         (200, '{"ok":true}'))

        self.assertEqual([script for script, _ in page.evaluations], [driver._FETCH_SCRIPT] * 2)
        post, get = page.fetches
        self.assertEqual((post['method'], post['path'], post['body'], post['timeout']),
                         ('POST', ENROLL_PATH, body, 2500))
        self.assertEqual({name: post['headers'].get(name) for name in headers}, headers)
        self.assertEqual(post['headers'].get('oai-device-id'), DEVICE)
        self.assertTrue(post['headers'].get('oai-session-id'))
        self.assertEqual((get['method'], get['path'], get['body'], get['timeout']), ('GET', INFO_PATH, None, 2500))
        self.assertEqual(get['headers'].get('accept'), '*/*')
        self.assertNotIn('authorization', get['headers'])  # nothing sticks from the previous request
        # The page receives exactly the fields its script takes apart.
        expected = script_parameters(driver._FETCH_SCRIPT)
        if expected is not None:
            self.assertEqual(set(post), expected)
            self.assertEqual(set(get), expected)

        plain = SignedInPage(CHATGPT)
        await driver.PageFetchTransport(plain).request('GET', INFO_PATH, headers={}, body=None)
        self.assertIsInstance(plain.fetches[0]['timeout'], int)
        self.assertGreater(plain.fetches[0]['timeout'], 0)

    async def test_session_header_is_stable_per_transport_and_distinct_between_transports(self):
        page = SignedInPage(CHATGPT)
        first, second = driver.PageFetchTransport(page), driver.PageFetchTransport(page)
        await first.request('GET', SESSION_PATH, headers={}, body=None)
        await first.request('POST', ENROLL_PATH, headers={}, body='{}')
        await second.request('GET', SESSION_PATH, headers={}, body=None)
        ids = [call['headers'].get('oai-session-id') for call in page.fetches]
        for value in ids:
            self.assertIsInstance(value, str)
            self.assertRegex(value, r'^[!-~]{8,128}$')  # a header-safe token, nothing more is promised
        self.assertEqual(ids[0], ids[1])
        self.assertNotEqual(ids[0], ids[2])

    async def test_device_header_comes_only_from_a_well_formed_oai_did_cookie(self):
        def did(value):
            return {'name': 'oai-did', 'value': value, 'domain': 'chatgpt.com', 'path': '/'}
        cases = [
            ('well formed', [did(DEVICE)], DEVICE),
            ('uuid shaped', [did('0f8fad5b-d9cb-469f-a165-70867728950e')], '0f8fad5b-d9cb-469f-a165-70867728950e'),
            ('among other cookies', [{'name': 'cf_clearance', 'value': 'x' * 12}, did(DEVICE)], DEVICE),
            ('no cookies at all', [], None),
            ('only other cookies', [{'name': 'oai-did-backup', 'value': DEVICE}], None),
            ('too short', [did('short')], None),
            ('too long', [did('d' * 200)], None),
            ('empty', [did('')], None),
            ('contains a space', [did('fixture device 0001')], None),
            ('contains a line break', [did(DEVICE + '\r\nx-injected: 1')], None),
            ('contains a quote', [did('"' + DEVICE + '"')], None),
            ('no value field', [{'name': 'oai-did'}], None),
        ]
        for label, cookies, expected in cases:
            with self.subTest(label):
                page = SignedInPage(CHATGPT, cookies=cookies)
                transport = driver.PageFetchTransport(page)
                for _ in range(2):
                    self.assertEqual(await transport.request('GET', INFO_PATH, headers={}, body=None), (200, '{}'))
                for call in page.fetches:
                    if expected is None:
                        self.assertNotIn('oai-device-id', call['headers'])
                    else:
                        self.assertEqual(call['headers'].get('oai-device-id'), expected)

    async def test_unreadable_cookies_do_not_break_the_request(self):
        page = SignedInPage(CHATGPT, respond={'status': 200, 'text': 'fixture'},
                            cookie_error=RuntimeError('Target page, context or browser has been closed'))
        transport = driver.PageFetchTransport(page)
        self.assertEqual(await transport.request('GET', INFO_PATH, headers={'accept': '*/*'}, body=None),
                         (200, 'fixture'))
        self.assertEqual(await transport.request('POST', ENROLL_PATH, headers={}, body='{}'), (200, 'fixture'))
        for call in page.fetches:
            self.assertNotIn('oai-device-id', call['headers'])
            self.assertTrue(call['headers'].get('oai-session-id'))

    async def test_page_answers_come_back_as_status_and_text(self):
        answers = [
            ({'status': 200, 'text': '{"mfa_enabled":true}'}, (200, '{"mfa_enabled":true}')),
            ({'status': 403, 'text': 'denied'}, (403, 'denied')),
            ({'status': 503, 'text': ''}, (503, '')),
            ({'status': 200, 'text': None}, (200, None)),  # the page reported null instead of a body
            ({'status': 0, 'text': ''}, (0, '')),  # a redirect, which the page does not follow
        ]
        for answer, expected in answers:
            with self.subTest(answer=answer):
                page = SignedInPage(CHATGPT, respond=answer)
                result = await driver.PageFetchTransport(page).request('GET', INFO_PATH, headers={}, body=None)
                self.assertEqual(result, expected)
                self.assertIsInstance(result[0], int)

    async def test_no_usable_answer_from_the_page_is_a_transport_error(self):
        unusable = [RuntimeError('Execution context was destroyed, most likely because of a navigation'),
                    asyncio.TimeoutError(), ValueError('origin'), KeyError('status'),
                    None, 'ok', 200, ['200', 'text'], {}, {'text': 'no status'},
                    {'status': None, 'text': 'x'}, {'status': '200', 'text': 'x'},
                    {'status': 200.5, 'text': 'x'}, {'status': True, 'text': 'x'}]
        for answer in unusable:
            with self.subTest(answer=repr(answer)):
                page = SignedInPage(CHATGPT, respond=answer)
                with self.assertRaises(MfaTransportError):
                    await driver.PageFetchTransport(page).request('GET', INFO_PATH, headers={}, body=None)
                self.assertEqual(len(page.fetches), 1)  # asked once, never repeated on its own

    async def test_page_that_never_answers_is_given_up_as_a_transport_error(self):
        async def never(_argument):
            await asyncio.Future()
        page = SignedInPage(CHATGPT, respond=never)
        with patch.object(driver, 'asyncio', FastAsyncio(scale=0.001)):
            with self.assertRaises(MfaTransportError):
                await asyncio.wait_for(driver.PageFetchTransport(page, timeout_seconds=5).request(
                    'POST', ACTIVATE_PATH, headers={}, body='{}'), 3)
        self.assertEqual(len(page.fetches), 1)

    async def test_cancelling_a_request_is_not_mistaken_for_a_transport_error(self):
        started = asyncio.Event()

        async def stall(_argument):
            started.set()
            await asyncio.Future()

        page = SignedInPage(CHATGPT, respond=stall)
        task = asyncio.ensure_future(
            driver.PageFetchTransport(page).request('GET', INFO_PATH, headers={}, body=None))
        await asyncio.wait_for(started.wait(), 3)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

    async def test_transport_errors_carry_neither_the_request_nor_the_page_error(self):
        code = '424242'
        enrolment = 'fixture-enrolment-session'
        body = json.dumps({'code': code, 'factor_type': 'totp', 'session_id': enrolment})
        headers = {'authorization': 'Bearer ' + TOKEN}

        def echo(argument):  # a page error that repeats everything it was given
            return RuntimeError('page.evaluate: ' + json.dumps(argument))

        page = SignedInPage(CHATGPT, respond=echo)
        transport = driver.PageFetchTransport(page)
        with self.assertRaises(MfaTransportError) as caught:
            await transport.request('POST', ACTIVATE_PATH, headers=headers, body=body)
        error = caught.exception
        self.assertIn(TOKEN, json.dumps(page.fetches))  # the page did get the request, so the echo is real
        shown = [str(error), repr(error), repr(error.args), repr(vars(error)),
                 ''.join(traceback.format_exception(error))]
        self.assert_nothing_private(shown, also=(code, enrolment))

    async def test_mfa_client_reads_a_redirect_as_refused_and_a_silent_page_as_unknown(self):
        answers = {SESSION_PATH: {'status': 200, 'text': json.dumps({'accessToken': TOKEN, 'user': {'email': EMAIL}})}}
        page = SignedInPage(CHATGPT, respond=lambda argument: answers.get(argument['path'], {'status': 0, 'text': ''}))
        client = ChatGPTMfaClient(driver.PageFetchTransport(page), expected_email=EMAIL)
        await client.open_session()

        with self.assertRaises(MfaError) as redirected:  # e.g. bounced to a login or challenge page
            await client.state()
        self.assertEqual(redirected.exception.outcome, 'rejected')

        answers[INFO_PATH] = RuntimeError('Target page, context or browser has been closed ' + TOKEN)
        with self.assertRaises(MfaError) as silent:
            await client.state()
        self.assertEqual(silent.exception.outcome, 'unknown')

        self.assertEqual([(call['method'], call['path']) for call in page.fetches],
                         [('GET', SESSION_PATH), ('GET', INFO_PATH), ('GET', INFO_PATH)])
        self.assertNotIn('authorization', page.fetches[0]['headers'])
        self.assertEqual(page.fetches[1]['headers'].get('authorization'), 'Bearer ' + TOKEN)
        for error in (redirected.exception, silent.exception):
            self.assert_nothing_private(str(error), repr(error), repr(vars(error)),
                                        ''.join(traceback.format_exception(error)))


class EmbeddedScriptTests(unittest.TestCase):
    """The two scripts run inside the signed-in page; these are their fixed safety properties."""

    def assert_pinned_and_bounded(self, script):
        check = re.search(r'''location\.origin\s*(?:!==|===)\s*(['"])https://chatgpt\.com\1''', script)
        self.assertIsNotNone(check, 'location.origin is not compared with https://chatgpt.com')
        request = re.search(r'\bfetch\s*\(', script)
        self.assertIsNotNone(request)
        self.assertLess(check.end(), request.start())  # checked before anything is sent
        self.assertRegex(script[check.end():request.start()], r'\b(?:throw|return)\b')  # a mismatch stops it
        self.assertEqual(len(re.findall(r'\bfetch\s*\(', script)), 1)
        self.assertEqual(set(re.findall(r'''https?://[^\s'"`)]+''', script)), {'https://chatgpt.com'})
        for option, value in (('credentials', 'include'), ('redirect', 'manual'), ('cache', 'no-store')):
            self.assertRegex(script, rf'''\b{option}\s*:\s*(['"]){value}\1''')
        self.assertRegex(script, r'new\s+AbortController\s*\(')
        self.assertRegex(script, r'\bsignal\s*:')
        self.assertRegex(script, r'setTimeout\s*\([^;]*\.abort\s*\(\s*\)[^;]*\btimeout\b')
        self.assertNotRegex(script, r'console\.|localStorage|sessionStorage|document\.cookie|postMessage|\beval\s*\(')

    def test_fetch_script_is_pinned_to_the_chatgpt_origin_and_bounded(self):
        script = driver._FETCH_SCRIPT
        self.assert_pinned_and_bounded(script)
        self.assertNotRegex(script, r'''\bfetch\s*\(\s*['"`]''')  # the target is never a fixed literal...
        self.assertRegex(script, r'\bpath\b')  # ...it is the path the caller asked for

    def test_probe_script_only_reports_whether_a_session_exists(self):
        script = driver._PROBE_SCRIPT
        self.assert_pinned_and_bounded(script)
        self.assertRegex(script, r'''\bfetch\s*\(\s*(['"])/api/auth/session\1''')
        self.assertRegex(script, r'^\s*async\s*\([^)]*\)\s*=>\s*\{')  # a block body: nothing returned implicitly
        answers = [expression.strip() for expression in re.findall(r'\breturn\b([^;}]*)', script)]
        self.assertTrue(any(answer.startswith('Boolean') for answer in answers))
        for answer in answers:  # every exit is a plain boolean; the token itself never leaves the page
            self.assertTrue(answer in ('false', 'true') or single_call(answer, 'Boolean'), answer)


NODE = shutil.which('node')
# Runs a script the way page.evaluate does (a function expression called with one argument), but
# with the page globals it touches replaced by recording stand-ins passed in as parameters.
SCRIPT_HARNESS = r'''
const input = __INPUT__;
const TARGET = 'https://chatgpt.com';
const HUNG = Symbol('hung');

function build(source, env) {
  const names = Object.keys(env);
  return new Function(...names, 'return (' + source + '\n);')(...names.map((name) => env[name]));
}

function reply(status, text, type) {
  return {status, type: type || 'basic', ok: status >= 200 && status <= 299,
          text: async () => text, json: async () => JSON.parse(text)};
}

// A request that never completes; it fails only when the caller aborts it.
function stalled(options) {
  return new Promise((resolve, reject) => {
    options.signal.addEventListener('abort', () => reject(new Error('aborted')));
  });
}

async function run(source, origin, argument, respond) {
  const calls = [];
  const env = {
    location: {origin}, navigator: {language: 'en-GB'}, AbortController, setTimeout, clearTimeout,
    fetch: (target, options) => {
      const sent = options || {};
      let resolved = null;  // where a browser would really send it, seen from this page
      try { resolved = new URL(String(target), origin + '/').href; } catch (error) { resolved = null; }
      calls.push({resolved, method: sent.method === undefined ? null : sent.method,
                  headers: sent.headers || null, body: sent.body === undefined ? null : sent.body,
                  credentials: sent.credentials || null, cache: sent.cache || null,
                  redirect: sent.redirect || null,
                  abortable: Boolean(sent.signal && typeof sent.signal.addEventListener === 'function')});
      return Promise.resolve().then(() => respond(sent));
    },
  };
  const record = {calls, threw: false, hung: false, kind: null, value: null};
  let watchdog;
  const limit = new Promise((resolve) => { watchdog = setTimeout(() => resolve(HUNG), 1500); });
  try {
    const value = await Promise.race([build(source, env)(argument), limit]);
    if (value === HUNG) {
      record.hung = true;  // the script neither answered nor gave up on its own
    } else {
      record.kind = value === null ? 'null' : typeof value;
      record.value = value === undefined ? null : value;
    }
  } catch (error) {
    record.threw = true;
  } finally {
    clearTimeout(watchdog);
  }
  return record;
}

async function main() {
  const out = {compiled: {}, foreign: {}, signed_out: {}, probe_foreign: {}};
  const inert = {location: {origin: TARGET}, navigator: {}, AbortController, setTimeout, clearTimeout,
                 fetch: () => { throw new Error('unused'); }};
  for (const name of ['fetch', 'probe']) {
    try { out.compiled[name] = typeof build(input[name], inert); } catch (error) { out.compiled[name] = 'error'; }
  }

  const request = (extra) => Object.assign(
    {path: input.path, method: 'GET', headers: input.headers, body: null, timeout: 2000}, extra);
  const answer = () => reply(200, input.answer);
  out.get = await run(input.fetch, TARGET, request({}), answer);
  out.post = await run(input.fetch, TARGET, request({method: 'POST', body: input.payload}), () => reply(403, 'denied'));
  out.redirect = await run(input.fetch, TARGET, request({}), () => reply(0, '', 'opaqueredirect'));
  out.stalled = await run(input.fetch, TARGET, request({timeout: 5}), stalled);
  out.offline = await run(input.fetch, TARGET, request({}), () => { throw new TypeError('Failed to fetch'); });
  for (const origin of input.foreign) out.foreign[origin] = await run(input.fetch, origin, request({}), answer);

  const session = (payload, status) => () => reply(status || 200, JSON.stringify(payload));
  out.signed_in = await run(input.probe, TARGET, 2000,
                            session({accessToken: input.token, user: {email: 'member@example.com'}}));
  const signedOut = {
    empty_token: session({accessToken: ''}),
    missing_token: session({user: {email: 'member@example.com'}}),
    non_string_token: session({accessToken: 12345}),
    empty_object: session({}),
    null_body: session(null),
    unauthorized: session({accessToken: input.token}, 401),
    server_error: session({accessToken: input.token}, 503),
    redirect: () => reply(0, '', 'opaqueredirect'),
    not_json: () => reply(200, '<html>challenge</html>'),
    offline: () => { throw new TypeError('Failed to fetch'); },
  };
  for (const name of Object.keys(signedOut)) {
    out.signed_out[name] = await run(input.probe, TARGET, 2000, signedOut[name]);
  }
  out.probe_stalled = await run(input.probe, TARGET, 5, stalled);
  for (const origin of input.foreign) {
    out.probe_foreign[origin] = await run(input.probe, origin, 2000, session({accessToken: input.token}));
  }
  return out;
}

const finish = (text, code) => process.stdout.write(text, () => process.exit(code));
if (typeof AbortController !== 'function') {
  finish(JSON.stringify({unsupported: true}), 0);
} else {
  main().then((out) => finish(JSON.stringify(out), 0),
              (error) => { process.stderr.write(String((error && error.stack) || error), () => process.exit(1)); });
}
'''


@unittest.skipUnless(NODE, 'node is not installed; the embedded scripts are then only checked as text')
class EmbeddedScriptBehaviourTests(unittest.TestCase):
    """Runs both scripts in Node against stand-ins for the page globals: no browser, no network."""

    FOREIGN = ['https://auth.openai.com', 'https://chatgpt.com.evil.example', 'http://chatgpt.com',
               'https://chatgpt.com:8443', 'null']
    HEADERS = {'accept': '*/*', 'authorization': 'Bearer ' + TOKEN, 'oai-session-id': 'fixture-session'}
    ANSWER = '{"mfa_enabled":false}'
    PAYLOAD = '{"factor_type":"totp"}'

    @classmethod
    def setUpClass(cls):
        payload = {'fetch': driver._FETCH_SCRIPT, 'probe': driver._PROBE_SCRIPT, 'token': TOKEN, 'path': INFO_PATH,
                   'headers': cls.HEADERS, 'answer': cls.ANSWER, 'payload': cls.PAYLOAD, 'foreign': cls.FOREIGN}
        finished = subprocess.run([NODE, '-'], input=SCRIPT_HARNESS.replace('__INPUT__', json.dumps(payload)),
                                  capture_output=True, encoding='utf-8', timeout=60)
        if finished.returncode != 0:
            raise AssertionError('the script harness itself failed: ' + finished.stderr[-2000:])
        cls.report = json.loads(finished.stdout)
        if cls.report.get('unsupported'):
            raise unittest.SkipTest('this Node has no AbortController')

    def test_both_scripts_are_function_expressions_that_page_evaluate_can_call(self):
        self.assertEqual(self.report['compiled'], {'fetch': 'function', 'probe': 'function'})

    def test_fetch_script_sends_exactly_the_given_request_with_the_page_session(self):
        get, post = self.report['get'], self.report['post']
        self.assertEqual((get['threw'], get['value']), (False, {'status': 200, 'text': self.ANSWER}))
        self.assertEqual((post['threw'], post['value']), (False, {'status': 403, 'text': 'denied'}))
        for record, method, body in ((get, 'GET', None), (post, 'POST', self.PAYLOAD)):
            (call,) = record['calls']
            self.assertEqual((call['resolved'], call['method'], call['body']),
                             ('https://chatgpt.com' + INFO_PATH, method, body))
            self.assertEqual((call['credentials'], call['cache'], call['redirect']),
                             ('include', 'no-store', 'manual'))
            self.assertTrue(call['abortable'])
            for name, value in self.HEADERS.items():
                self.assertEqual(call['headers'].get(name), value)

    def test_fetch_script_sends_nothing_from_any_other_origin(self):
        for origin in self.FOREIGN:
            with self.subTest(origin=origin):
                record = self.report['foreign'][origin]
                self.assertTrue(record['threw'])  # page.evaluate fails: "no response" for the caller
                self.assertEqual(record['calls'], [])

    def test_fetch_script_reports_a_redirect_as_zero_and_no_answer_as_a_failure(self):
        redirect = self.report['redirect']
        self.assertFalse(redirect['threw'])
        self.assertEqual(redirect['value']['status'], 0)
        for name in ('stalled', 'offline'):  # aborted by its own timer / network failure
            with self.subTest(name):
                self.assertTrue(self.report[name]['threw'])
                (call,) = self.report[name]['calls']
                self.assertTrue(call['abortable'])

    def test_probe_script_answers_true_or_false_and_nothing_else(self):
        signed_in = self.report['signed_in']
        self.assertEqual((signed_in['threw'], signed_in['kind'], signed_in['value']), (False, 'boolean', True))
        (call,) = signed_in['calls']
        self.assertEqual((call['resolved'], call['credentials'], call['cache'], call['redirect']),
                         ('https://chatgpt.com' + SESSION_PATH, 'include', 'no-store', 'manual'))
        self.assertTrue(call['abortable'])
        quiet = {**self.report['signed_out'], 'stalled': self.report['probe_stalled'], **self.report['probe_foreign']}
        self.assertGreaterEqual(len(quiet), 10 + 1 + len(self.FOREIGN))
        for name, record in quiet.items():
            with self.subTest(name):
                self.assertEqual((record['threw'], record['kind'], record['value']), (False, 'boolean', False))
        for origin in self.FOREIGN:
            self.assertEqual(self.report['probe_foreign'][origin]['calls'], [])
        self.assertNotIn(TOKEN, json.dumps([signed_in, quiet]))


class ResetLifecycleTests(NoLeaks, unittest.IsolatedAsyncioTestCase):
    """run_assisted_browser(action='reset_totp'): launch rules and the critical section."""

    def setUp(self):
        self.browser = FakeBrowser()
        self.playwright = FakePlaywright(self.browser)
        self.factory = Mock(return_value=self.playwright)
        modules = patch.dict(sys.modules, {
            'playwright.async_api': types.SimpleNamespace(async_playwright=self.factory)})
        modules.start()
        self.addCleanup(modules.stop)

    def start(self, **overrides):
        options = {'email': EMAIL, 'password': PASSWORD, 'totp_secret': SECRET, 'authorize_url': '',
                   'redirect_uri': '', 'action': 'reset_totp', 'cancel': asyncio.Event(),
                   'on_stage': AsyncMock(), 'on_callback': None, 'on_mfa': AsyncMock(), **overrides}
        return driver.run_assisted_browser(**options)

    async def run_browser(self, **overrides):
        return await asyncio.wait_for(self.start(**overrides), 5)

    async def test_reset_without_its_routine_is_refused_before_any_browser_is_launched(self):
        stage = AsyncMock()
        page_driver = AsyncMock()
        with patch.object(driver, '_drive_page', page_driver):
            omitted = await driver.run_assisted_browser(
                email=EMAIL, password=PASSWORD, totp_secret=SECRET, authorize_url='', redirect_uri='',
                action='reset_totp', cancel=asyncio.Event(), on_stage=stage, on_callback=None)
            empty = await self.run_browser(on_mfa=None, on_stage=stage)
        for result in (omitted, empty):
            self.assertIs(result['ok'], False)
            self.assertEqual(result['error_code'], 'browser_input_invalid')
            self.assert_nothing_private(result)
        self.factory.assert_not_called()
        self.playwright.launch.assert_not_awaited()
        page_driver.assert_not_awaited()
        stage.assert_not_awaited()

    async def test_unknown_actions_are_still_refused_before_launch(self):
        page_driver = AsyncMock()
        for action in ('reset', 'RESET_TOTP', 'reset_totp ', 'disable_totp', 'delete_account', '', None):
            with self.subTest(action=action):
                on_mfa = AsyncMock()
                with patch.object(driver, '_drive_page', page_driver):
                    result = await self.run_browser(action=action, on_mfa=on_mfa)
                self.assertEqual(result['error_code'], 'browser_input_invalid')
                on_mfa.assert_not_awaited()
        self.factory.assert_not_called()
        self.playwright.launch.assert_not_awaited()
        page_driver.assert_not_awaited()

    async def test_reset_opens_a_visible_chatgpt_window_and_hands_routine_and_guard_to_the_page_driver(self):
        on_mfa = AsyncMock()
        outcome = {'ok': True, 'state': 'success', 'message': 'fixture flow result'}
        received = {}

        async def drive(page, **kwargs):
            received.update(kwargs, page=page, critical=kwargs['guard']['critical'])
            return outcome

        with patch.object(driver, '_drive_page', drive):
            result = await self.run_browser(on_mfa=on_mfa)
        self.assertEqual(result, outcome)
        self.assertIs(received['page'], self.browser.page)
        self.assertEqual(received['action'], 'reset_totp')
        self.assertIs(received['on_mfa'], on_mfa)
        self.assertIs(received['critical'], False)
        self.playwright.launch.assert_awaited_once()
        self.assertIs(self.playwright.launch.call_args.kwargs.get('headless'), False)
        (opened,) = self.browser.page.gotos
        self.assertEqual((urlsplit(opened).scheme, urlsplit(opened).hostname), ('https', 'chatgpt.com'))
        self.assertTrue(self.browser.closed)

    async def test_stop_request_during_the_reset_waits_for_the_reset_and_returns_its_own_result(self):
        cancel = asyncio.Event()
        outcome = {'ok': False, 'state': 'manual_required', 'error_code': 'mfa_incomplete',
                   'message': 'fixture flow result'}
        seen = {}

        async def drive(page, **kwargs):
            kwargs['guard']['critical'] = True  # the reset routine has started...
            cancel.set()  # ...and the user presses stop
            try:
                await asyncio.sleep(0.03)  # the routine is still between two of its requests
            except asyncio.CancelledError:
                seen['cut_off'] = True
                raise
            kwargs['guard']['critical'] = False
            return outcome

        with patch.object(driver, '_drive_page', drive):
            result = await self.run_browser(cancel=cancel)
        self.assertEqual(result, outcome)
        self.assertNotIn('cut_off', seen)
        self.assertTrue(self.browser.closed)

    async def test_deadline_during_the_reset_waits_for_the_reset_and_returns_its_own_result(self):
        fast = FastAsyncio(scale=0.02)
        outcome = {'ok': True, 'state': 'success', 'message': 'fixture flow result'}
        seen = {}

        async def drive(page, **kwargs):
            kwargs['guard']['critical'] = True
            try:
                await asyncio.wait_for(fast.timed_out.wait(), 3)  # the deadline passes in the middle of the reset
                await asyncio.sleep(0.01)
            except asyncio.CancelledError:
                seen['cut_off'] = True
                raise
            kwargs['guard']['critical'] = False
            return outcome

        with patch.object(driver, 'asyncio', fast), patch.object(driver, '_drive_page', drive):
            result = await self.run_browser(timeout_seconds=1)
        self.assertEqual(result, outcome)
        self.assertNotIn('cut_off', seen)
        self.assertTrue(self.browser.closed)

    async def test_stop_request_outside_the_reset_still_cancels_at_once(self):
        cancel = asyncio.Event()
        seen = {}

        async def drive(page, **kwargs):
            seen['critical'] = kwargs['guard']['critical']
            cancel.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                seen['cut_off'] = True
                raise

        with patch.object(driver, '_drive_page', drive):
            # Far below the real grace period: nothing waited for a reset that never started.
            result = await asyncio.wait_for(self.start(cancel=cancel), 2)
        self.assertIs(seen['critical'], False)
        self.assertEqual((result['state'], result['error_code']), ('cancelled', 'cancelled'))
        self.assertTrue(seen.get('cut_off'))
        self.assertTrue(self.browser.closed)

    async def test_reset_that_outlives_the_grace_after_a_stop_request_is_cut_off_and_reported_cancelled(self):
        cancel = asyncio.Event()
        loop = asyncio.get_running_loop()
        seen = {}

        async def drive(page, **kwargs):
            kwargs['guard']['critical'] = True
            cancel.set()
            seen['asked'] = loop.time()
            try:
                await asyncio.Future()  # the routine never comes back
            except asyncio.CancelledError:
                seen['cut_off'] = loop.time()
                raise

        with patch.object(driver, 'CRITICAL_GRACE_SECONDS', 0.05), patch.object(driver, '_drive_page', drive):
            result = await self.run_browser(cancel=cancel)
        self.assertIs(result['ok'], False)
        self.assertEqual((result['state'], result['error_code']), ('cancelled', 'cancelled'))
        self.assertGreaterEqual(seen['cut_off'] - seen['asked'], 0.01)  # it was given the grace first
        self.assertTrue(self.browser.closed)

    async def test_reset_that_outlives_the_grace_after_the_deadline_is_cut_off_and_reported_as_a_timeout(self):
        fast = FastAsyncio(scale=0.02)
        seen = {}

        async def drive(page, **kwargs):
            kwargs['guard']['critical'] = True
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                seen['cut_off'] = True
                raise

        with patch.object(driver, 'asyncio', fast), patch.object(driver, 'CRITICAL_GRACE_SECONDS', 1.5), \
                patch.object(driver, '_drive_page', drive):
            result = await self.run_browser(timeout_seconds=1)
        self.assertIs(result['ok'], False)
        self.assertEqual(result['error_code'], 'browser_timeout')
        self.assertIn(1.5, fast.timeouts)  # the extra wait was the configured grace period
        self.assertTrue(seen.get('cut_off'))
        self.assertTrue(self.browser.closed)

    async def test_hard_cancellation_during_the_grace_still_closes_the_window(self):
        cancel = asyncio.Event()
        entered = asyncio.Event()
        seen = {}

        async def drive(page, **kwargs):
            kwargs['guard']['critical'] = True
            cancel.set()
            entered.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                seen['cut_off'] = True
                raise

        with patch.object(driver, '_drive_page', drive):
            task = asyncio.ensure_future(self.start(cancel=cancel))
            await asyncio.wait_for(entered.wait(), 3)
            await asyncio.sleep(0.02)  # the stop request has reached the grace wait by now
            self.assertFalse(task.done())
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertTrue(seen.get('cut_off'))
        self.assertTrue(self.browser.closed)

    async def test_login_and_reset_requests_run_through_the_window_end_to_end(self):
        def official(argument):  # the "official API" as the signed-in page would reach it
            if page.url != CHATGPT:
                return RuntimeError('request issued from the wrong page')
            if (argument['method'], argument['path']) == ('GET', SESSION_PATH):
                return {'status': 200, 'text': json.dumps({'accessToken': TOKEN, 'user': {'email': EMAIL}})}
            if (argument['method'], argument['path']) == ('GET', INFO_PATH):
                return {'status': 200, 'text': json.dumps({
                    'mfa_enabled': True, 'factors': {'totp': [{'id': 'factor-old'}]}})}
            return {'status': 404, 'text': '{}'}

        page = self.browser.page = SignedInPage('about:blank', respond=official, lands_on=LOGIN,
                                                cookies=[{'name': 'oai-did', 'value': DEVICE}])
        typed = []

        async def fill(_page, selector, value):
            typed.append(selector)
            if selector == driver.OTP_SELECTOR:
                page.url = CHATGPT
            return True

        seen = {}

        async def reset(transport, proof):
            seen['proof'] = dict(proof)
            client = ChatGPTMfaClient(transport, expected_email=EMAIL)
            try:
                await client.open_session()
                seen['state'] = await client.state()
            finally:
                client.close()
            return {'ok': True, 'success': True, 'status': 'success', 'candidate': NEW_SECRET}

        stages = []
        with patch.object(driver, 'asyncio', FastAsyncio()), patch.object(driver, '_fill_and_submit', fill), \
                patch.object(driver, '_snapshot', snapshots(page, [EMAIL_FORM, PASSWORD_FORM, TOTP_FORM])):
            result = await self.run_browser(on_mfa=reset, on_stage=lambda name, message: stages.append((name, message)))

        self.assertIs(result['ok'], True)
        self.assertEqual(typed, [driver.EMAIL_SELECTOR, driver.PASSWORD_SELECTOR, driver.OTP_SELECTOR])
        self.assertEqual(seen['proof'], {'totp_accepted': True})
        self.assertIs(seen['state'].enabled, True)
        self.assertEqual(seen['state'].active_factor_id, 'factor-old')
        session, info = page.fetches
        self.assertEqual((session['method'], session['path']), ('GET', SESSION_PATH))
        self.assertNotIn('authorization', session['headers'])
        self.assertEqual((info['method'], info['path']), ('GET', INFO_PATH))
        self.assertEqual(info['headers'].get('authorization'), 'Bearer ' + TOKEN)
        self.assertEqual((info['headers'].get('x-openai-target-path'), info['headers'].get('x-openai-target-route')),
                         (INFO_PATH, INFO_PATH))
        self.assertEqual(session['headers'].get('oai-session-id'), info['headers'].get('oai-session-id'))
        self.assertEqual(info['headers'].get('oai-device-id'), DEVICE)
        self.assertTrue(self.browser.closed)
        self.assert_nothing_private(result, stages, seen['proof'])
