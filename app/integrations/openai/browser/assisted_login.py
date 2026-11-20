"""Visible, single-account assistance using an ordinary ephemeral browser.

Only already-existing login credentials are submitted. Security challenges,
consent and account recovery belong to the user. The one account-security change
made here is the explicitly requested ``reset_totp`` action: once the page is
signed in, the caller's MFA routine talks to the official API through the page
itself. No browser state, page content, callback URL or secret is logged, and
nothing but the fixed result of that routine is returned.
"""
from __future__ import annotations

import asyncio
import contextlib
import inspect
import math
import re
import time
import uuid
from urllib.parse import parse_qs, unquote, urljoin, urlsplit

from app.integrations.openai.mfa import MfaTransportError, generate_totp

ACTIONS = frozenset({'oauth', 'security', 'logout_all', 'reset_totp'})
# A started reset is not cut off between its own bounded requests.
CRITICAL_GRACE_SECONDS = 100
SESSION_PROBE_SECONDS = 3.0
OFFICIAL_HOSTS = frozenset({'auth.openai.com', 'auth0.openai.com', 'chatgpt.com'})
AUTH_HOST = 'auth.openai.com'
CALLBACK_HOSTS = frozenset({'localhost', '127.0.0.1', '::1'})
EMAIL_SELECTOR = 'input[type="email"], input[name="email"], input[name="username"]'
PASSWORD_SELECTOR = 'input[type="password"]'
OTP_SELECTOR = ('input[autocomplete="one-time-code"], input[name="code"], '
                'input[name="otp"], input[name="totp"], input[inputmode="numeric"]')
CHALLENGE_SELECTOR = ('iframe[src*="challenges.cloudflare.com"], iframe[src*="recaptcha"], '
                      'iframe[src*="hcaptcha"], .cf-turnstile, .g-recaptcha, .h-captcha')
PROFILE_SELECTOR = '[data-testid="profile-button"], [data-testid="accounts-profile-button"]'


def _official_origin(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        return (parsed.scheme == 'https' and parsed.hostname in OFFICIAL_HOSTS
                and parsed.port in (None, 443) and parsed.username is None
                and parsed.password is None and not any(ord(c) < 33 for c in url))
    except (ValueError, TypeError):
        return False


def _credential_origin(url: str) -> bool:
    return _official_origin(url) and urlsplit(url).hostname == AUTH_HOST


def _chatgpt_origin(url: str) -> bool:
    return _official_origin(url) and urlsplit(url).hostname == 'chatgpt.com'


def _valid_redirect(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        return (parsed.scheme == 'http' and parsed.hostname in CALLBACK_HOSTS
                and parsed.port is not None and 1 <= parsed.port <= 65535
                and parsed.username is None and parsed.password is None
                and parsed.path.startswith('/') and not parsed.query and not parsed.fragment
                and '?' not in url and '#' not in url
                and not any(ord(c) < 33 for c in url))
    except (ValueError, TypeError):
        return False


def matches_callback(url: str, redirect_uri: str) -> bool:
    if not _valid_redirect(redirect_uri):
        return False
    try:
        actual, expected = urlsplit(url), urlsplit(redirect_uri)
        return (actual.scheme == expected.scheme and actual.hostname == expected.hostname
                and actual.port == expected.port and actual.path == expected.path
                and actual.username is None and actual.password is None
                and not actual.fragment and not any(ord(c) < 33 for c in url))
    except (TypeError, ValueError):
        return False


def classify_login_page(url: str, text: str = '', *, has_email: bool = False,
                        has_password: bool = False, has_otp: bool = False,
                        has_challenge: bool = False, logged_in: bool = False) -> str:
    """Conservative page classifier. Ambiguous OTP and consent stay manual."""
    if not _official_origin(url):
        return 'untrusted_origin'
    body = str(text or '').lower()
    path = urlsplit(url).path.lower()
    if has_challenge or re.search(r'verify (?:you are|you.re) human|checking your browser|'
                                 r'complete the security check|captcha|人机验证|验证您是人类|安全验证', body):
        return 'challenge'
    if re.search(r'too many (?:requests|attempts)|rate.limit|try again later|请求过于频繁|尝试次数过多', body):
        return 'rate_limited'
    if re.search(r'account (?:is |has been )?(?:deactivated|disabled)|账号已停用|账户已停用', body):
        return 'account_unavailable'
    if re.search(r'incorrect (?:email or )?password|wrong password|invalid password|'
                 r'(?:wrong|incorrect|invalid) (?:authentication |authenticator |verification |security |totp |otp )?code|'
                 r'密码错误|密码不正确|验证码错误|验证码无效', body):
        return 'credentials_rejected'
    if re.search(r'signup|sign-up|create-account|reset-password|new-password|recovery', path):
        return 'account_change'
    if re.search(r'create (?:your |an? )?account|create a password|set (?:a |new )?password|'
                 r'创建账号|创建账户|设置密码|重置密码', body) and has_password:
        return 'account_change'
    if re.search(r'add-phone|phone-verification', path) or re.search(r'sms code|text message|短信验证码', body):
        return 'phone_verification'
    if 'consent' in path or (not any((has_email, has_password, has_otp))
                           and re.search(r'authorize access|allow access|terms of service|服务条款|授权访问', body)):
        return 'consent'
    if urlsplit(url).hostname == 'chatgpt.com' and logged_in:
        return 'authenticated'
    # auth0 is allowed for observation only; credentials are never injected there.
    if not _credential_origin(url):
        return 'manual_required'
    if has_otp:
        if (re.search(r'email-verification|verify-email', path)
                or re.search(r'check (?:your )?(?:email|inbox)|sent.{0,50}(?:email|inbox)|'
                             r'(?:email|inbox).{0,40}(?:sent|verification code)|'
                             r'邮箱验证码|电子邮件验证码|查看.{0,8}(?:邮箱|邮件)|验证码.{0,20}(?:发送至|已发送)', body)):
            return 'email_verification'
        if re.search(r'authenticator|authentication app|totp|身份验证器|验证器|验证应用', body) or re.search(r'/mfa/totp(?:/|$)', path):
            return 'totp'
        return 'ambiguous_otp'
    if has_password:
        return 'password'
    if has_email:
        return 'email'
    return 'manual_required'


def _proxy_options(proxy: str) -> dict | None:
    if not proxy:
        return None
    try:
        if not isinstance(proxy, str) or any(ord(c) < 33 for c in proxy):
            raise ValueError
        parsed = urlsplit(proxy)
        if (parsed.scheme not in {'http', 'https', 'socks5'} or not parsed.hostname
                or parsed.port is None or not 1 <= parsed.port <= 65535
                or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
            raise ValueError
        if parsed.scheme == 'socks5' and (parsed.username is not None or parsed.password is not None):
            raise ValueError
        host = f'[{parsed.hostname}]' if ':' in parsed.hostname else parsed.hostname
        result = {'server': f'{parsed.scheme}://{host}:{parsed.port}',
                  'bypass': 'localhost,127.0.0.1,[::1]'}
        if parsed.username is not None:
            result['username'] = unquote(parsed.username)
            result['password'] = unquote(parsed.password or '')
        return result
    except (ValueError, TypeError):
        raise ValueError('Unsupported fixed browser proxy') from None


async def _call(callback, *args):
    if callback is None:
        return None
    result = callback(*args)
    return await result if inspect.isawaitable(result) else result


async def _visible(locator):
    for index in range(min(await locator.count(), 12)):
        candidate = locator.nth(index)
        if await candidate.is_visible():
            return candidate
    return None


async def _snapshot(page) -> dict:
    return {'url': page.url, 'text': (await page.locator('body').inner_text(timeout=1500))[:24000],
            'has_email': bool(await _visible(page.locator(EMAIL_SELECTOR))),
            'has_password': bool(await _visible(page.locator(PASSWORD_SELECTOR))),
            'has_otp': bool(await _visible(page.locator(OTP_SELECTOR))),
            'has_challenge': bool(await _visible(page.locator(CHALLENGE_SELECTOR))),
            'logged_in': bool(await _visible(page.locator(PROFILE_SELECTOR)))}


async def _fill_and_submit(page, selector: str, value: str) -> bool:
    if not _credential_origin(page.url):
        return False
    target = await _visible(page.locator(selector))
    if target is None:
        return False
    form = target.locator('xpath=ancestor::form[1]')
    if await form.count() != 1:
        return False
    action = await form.get_attribute('action')
    if not _credential_origin(urljoin(page.url, action or '')):
        return False
    await target.fill(value)
    action = await form.get_attribute('action')
    if not _credential_origin(page.url) or not _credential_origin(urljoin(page.url, action or '')):
        return False
    await target.press('Enter')
    return True


async def _click_named(page, roles, names) -> bool:
    for role in roles:
        candidate = await _visible(page.get_by_role(role, name=names))
        if candidate is not None:
            await candidate.click()
            return True
    return False


async def _open_security_settings(page) -> bool:
    """Navigate visible menus only. Never operate an authentication factor."""
    if not _official_origin(page.url) or urlsplit(page.url).hostname != 'chatgpt.com':
        return False
    profile = await _visible(page.locator(PROFILE_SELECTOR))
    if profile is None:
        return False
    await profile.click()
    if not await _click_named(page, ('menuitem', 'button'), re.compile(r'^(Settings|设置|設定)$', re.I)):
        return False
    return await _click_named(page, ('tab', 'button', 'link'), re.compile(r'^(Security|安全|安全性)$', re.I))


# Runs inside the signed-in page: same origin, the page's own cookies and network stack.
_FETCH_SCRIPT = """async ({path, method, headers, body, timeout}) => {
  if (location.origin !== 'https://chatgpt.com') throw new Error('origin');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const sent = Object.assign({}, headers);
    if (!sent['oai-language']) sent['oai-language'] = navigator.language || 'en-US';
    const target = new URL(path, location.origin);
    if (target.origin !== location.origin) throw new Error('origin');
    const response = await fetch(target.href, {method, headers: sent, body: body === null ? undefined : body,
      credentials: 'include', cache: 'no-store', redirect: 'manual', signal: controller.signal});
    if (response.type === 'opaqueredirect') return {status: 0, text: ''};
    const text = await response.text();
    return {status: response.status, text: text.length > 262144 ? null : text};
  } finally { clearTimeout(timer); }
}"""
# Answers only whether a web session exists; the token never leaves the page here.
_PROBE_SCRIPT = """async (timeout) => {
  if (location.origin !== 'https://chatgpt.com') return false;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch('/api/auth/session', {credentials: 'include', cache: 'no-store',
      redirect: 'manual', headers: {accept: 'application/json'}, signal: controller.signal});
    if (!response.ok) return false;
    const data = await response.json();
    return Boolean(data && typeof data.accessToken === 'string' && data.accessToken);
  } catch (_) { return false; } finally { clearTimeout(timer); }
}"""


class PageFetchTransport:
    """Same-origin requests issued by the signed-in chatgpt.com page itself."""

    def __init__(self, page, *, timeout_seconds: float = 15):
        self._page = page
        self._timeout = float(timeout_seconds)
        self._session_id = str(uuid.uuid4())
        self._device_id: str | None = None

    async def _device(self) -> str:
        if self._device_id is None:
            value = ''
            with contextlib.suppress(Exception):
                for cookie in await self._page.context.cookies('https://chatgpt.com'):
                    if cookie.get('name') == 'oai-did':
                        value = str(cookie.get('value') or '')
            self._device_id = value if re.fullmatch(r'[A-Za-z0-9._-]{8,80}', value) else ''
        return self._device_id

    async def request(self, method: str, path: str, *, headers: dict, body: str | None):
        """Return (status, text). Any failure to obtain a response is MfaTransportError."""
        if (method not in {'GET', 'POST'} or not isinstance(path, str)
                or not re.fullmatch(r'/[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*', path)
                or not _chatgpt_origin(self._page.url)):
            raise MfaTransportError()
        sent = {**headers, 'oai-session-id': self._session_id}
        device = await self._device()
        if device:
            sent['oai-device-id'] = device
        try:
            result = await asyncio.wait_for(self._page.evaluate(_FETCH_SCRIPT, {
                'path': path, 'method': method, 'headers': sent, 'body': body,
                'timeout': int(self._timeout * 1000)}), timeout=self._timeout + 10)
        except Exception:
            # Thrown page errors, navigation, a closed window and timeouts all mean "no response".
            raise MfaTransportError() from None
        finally:
            sent.clear()
        status = result.get('status') if isinstance(result, dict) else None
        if not isinstance(status, int) or isinstance(status, bool):
            raise MfaTransportError()
        text = result.get('text')
        return status, text if isinstance(text, str) else None


async def _probe_session(page) -> bool:
    try:
        return (await asyncio.wait_for(page.evaluate(_PROBE_SCRIPT, 8000), timeout=12)) is True
    except Exception:
        return False


async def _drive_page(page, *, action, email, password, totp_secret, redirect_uri,
                      captured, on_stage, on_callback, on_mfa=None, guard=None) -> dict:
    submitted = set()
    last_stage = None
    user_handoff = False
    security_handoff = False
    authenticated = False
    unknown_since = None
    login_entry_clicked = False
    last_probe = 0.0
    totp_at = None
    totp_lingered = False

    async def report(stage, message):
        nonlocal last_stage
        if last_stage != stage:
            last_stage = stage
            await _call(on_stage, stage, message)

    async def run_mfa():
        await report('authenticated', '官方页面已登录，正在读取账号会话')
        # Proof for the caller: the only sign-in code was generated here, the form left promptly
        # afterwards, and the user never had to take over.
        proof = {'totp_accepted': totp_at is not None and not user_handoff and not totp_lingered}
        if guard is not None:
            guard['critical'] = True
        try:
            outcome = await _call(on_mfa, PageFetchTransport(page), proof)
        finally:
            if guard is not None:
                guard['critical'] = False
        if isinstance(outcome, dict) and (outcome.get('ok') is True or outcome.get('success') is True):
            return {'ok': True, 'state': 'success', 'message': '2FA 重设流程已完成'}
        return {'ok': False, 'state': 'manual_required', 'error_code': 'mfa_incomplete',
                'message': '2FA 重设未完成，请查看任务结果'}

    while True:
        if page.is_closed():
            return {'ok': False, 'state': 'manual_required', 'error_code': 'browser_closed',
                    'message': '浏览器已关闭，未确认本次操作结果'}
        if (action == 'reset_totp' and _chatgpt_origin(page.url)
                and not urlsplit(page.url).path.lower().startswith(('/auth/', '/api/'))
                and time.monotonic() - last_probe >= SESSION_PROBE_SECONDS):
            # A web session is the sign-in signal here; it does not depend on page markup.
            last_probe = time.monotonic()
            if await _probe_session(page):
                return await run_mfa()
        if action == 'oauth' and (captured.get('url') or matches_callback(page.url, redirect_uri)):
            callback_url = captured.pop('url', '') or page.url
            await report('exchanging', '已收到本次授权回调，正在核对并保存')
            result = await _call(on_callback, callback_url)
            callback_url = ''
            if isinstance(result, dict) and (result.get('ok') is True or result.get('success') is True):
                return {'ok': True, 'state': 'success', 'message': '授权回调已验证并完成保存'}
            return {'ok': False, 'state': 'failed', 'error_code': 'callback_rejected',
                    'message': '授权回调未通过核对，请在账号页面查看状态'}
        if security_handoff:
            # No DOM/page text reads after handoff: newly displayed MFA secrets
            # and recovery codes must stay exclusively under the user's control.
            if action == 'logout_all' and authenticated and _official_origin(page.url):
                path = urlsplit(page.url).path.lower()
                if path.startswith(('/auth/login', '/log-in', '/login')):
                    return {'ok': False, 'state': 'manual_required', 'error_code': 'logout_scope_unverified',
                            'message': '已观察到当前窗口回到登录页；全部会话是否退出需在官方页面核对'}
            await asyncio.sleep(0.3)
            continue
        if user_handoff:
            # Once the user takes over, only observe the exact callback URL or
            # the non-secret profile control. Do not inspect their page content.
            kind = 'manual_required'
            if (action != 'oauth' and _official_origin(page.url)
                    and urlsplit(page.url).hostname == 'chatgpt.com'
                    and await _visible(page.locator(PROFILE_SELECTOR))):
                kind = 'authenticated'
            if kind != 'authenticated':
                await asyncio.sleep(0.3)
                continue
        else:
            try:
                snap = await _snapshot(page)
            except Exception:
                await asyncio.sleep(0.3)
                continue
            kind = classify_login_page(**snap)
            # Drop page text immediately; it never enters events or results.
            snap.clear()
            if kind == 'totp' and totp_at is not None and time.monotonic() - totp_at > 4:
                totp_lingered = True  # still asked for a code: a later one may be typed by hand
        if kind == 'manual_required' and not user_handoff:
            if not login_entry_clicked and _official_origin(page.url):
                host = urlsplit(page.url).hostname
                names = (re.compile(r'^(Log in|登录|登入)$', re.I) if host == 'chatgpt.com'
                         else re.compile(r'^(Continue with email|使用邮箱继续|使用電子郵件繼續)$', re.I))
                if await _click_named(page, ('button', 'link'), names):
                    login_entry_clicked = True
                    unknown_since = None
                    await asyncio.sleep(0.3)
                    continue
            if unknown_since is None:
                unknown_since = time.monotonic()
            if time.monotonic() - unknown_since < 5:
                await asyncio.sleep(0.3)
                continue
        else:
            unknown_since = None
        if kind == 'authenticated' and action == 'reset_totp':
            return await run_mfa()
        if kind == 'authenticated' and action != 'oauth':
            authenticated = True
            await report('authenticated', '官方页面已显示登录状态，正在打开安全设置')
            opened = await _open_security_settings(page)
            security_handoff = True
            await report('awaiting_user', ('已打开官方安全设置。请亲自完成会话注销或 2FA 操作；新密钥不会被程序读取。'
                                          if opened else '已登录。请在官方窗口打开设置 → 安全，并亲自完成操作；新密钥不会被程序读取。'))
            continue
        if kind in {'rate_limited', 'account_unavailable', 'credentials_rejected'}:
            messages = {'rate_limited':'官方提示操作频繁，已停止自动提交，请稍后人工核对',
                        'account_unavailable':'官方提示账号不可用，已停止自动提交',
                        'credentials_rejected':'官方未接受登录资料，已停止自动提交，请人工核对'}
            await report(kind, messages[kind])
            user_handoff = True
        elif not user_handoff and kind in {'email', 'password', 'totp'} and kind not in submitted:
            if kind == 'totp' and not totp_secret:
                user_handoff = True
                await report('manual_required', '官方要求验证器验证码，请在浏览器中自行输入')
                continue
            value = email if kind == 'email' else password if kind == 'password' else generate_totp(totp_secret)
            submitted.add(kind)  # A rejected submission is never repeated automatically.
            if kind == 'totp':
                totp_at = time.monotonic()
            selector = EMAIL_SELECTOR if kind == 'email' else PASSWORD_SELECTOR if kind == 'password' else OTP_SELECTOR
            if await _fill_and_submit(page, selector, value):
                await report(kind, {'email':'已提交本次账号邮箱，尚未确认官方是否接受',
                                    'password':'已提交本次账号密码，尚未确认验证结果',
                                    'totp':'已提交验证器验证码，尚未确认验证结果'}[kind])
            else:
                user_handoff = True
                await report('manual_required', '登录表单不符合预期，请在官方窗口手动继续')
            value = ''
        elif kind not in {'email', 'password', 'totp'}:
            user_handoff = True
            messages = {'challenge':'官方要求安全验证，请在浏览器中自行处理；程序不会操作验证码',
                        'email_verification':'官方要求邮箱验证码，请在浏览器中自行输入',
                        'phone_verification':'官方要求手机验证，请在浏览器中自行处理',
                        'account_change':'页面进入注册或账号恢复，请人工核对；程序不会更改账号',
                        'consent':'官方要求确认授权或条款，请在浏览器中自行确认',
                        'untrusted_origin':'页面离开预期官方来源，已停止自动填写，请人工核对',
                        'ambiguous_otp':'验证码类型不明确，程序未填写，请在浏览器中自行核对'}
            await report(kind if kind in messages else 'manual_required',
                         messages.get(kind, '请在官方浏览器窗口继续登录或确认授权'))
        await asyncio.sleep(0.3)


async def run_assisted_browser(*, email: str, password: str, totp_secret: str,
                               authorize_url: str, redirect_uri: str, action: str,
                               cancel: asyncio.Event, on_stage, on_callback, on_mfa=None,
                               chrome_channel='chrome', proxy='', timeout_seconds=600) -> dict:
    """Run a visible ephemeral browser. Cancellation/timeout always closes it.

    While the ``reset_totp`` routine is running, a stop request or the deadline
    waits (bounded) for that routine instead of cutting it off half-way.
    """
    guard = {'critical': False}
    try:
        if action not in ACTIONS or (action == 'reset_totp' and on_mfa is None):
            raise ValueError
        if (not isinstance(email, str) or not email or len(email) > 255
                or not isinstance(password, str) or not password or len(password) > 4096
                or not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool)
                or not math.isfinite(timeout_seconds) or not 1 <= timeout_seconds <= 1200
                or chrome_channel not in {'chrome', 'chromium'}):
            raise ValueError
        if not isinstance(totp_secret, str):
            raise ValueError
        if totp_secret:
            generate_totp(totp_secret)
        proxy_config = _proxy_options(proxy)
        if action == 'oauth':
            query = parse_qs(urlsplit(authorize_url).query)
            if (not _credential_origin(authorize_url) or urlsplit(authorize_url).path != '/oauth/authorize'
                    or not _valid_redirect(redirect_uri) or query.get('redirect_uri') != [redirect_uri]
                    or query.get('response_type') != ['code'] or len(query.get('state', [])) != 1
                    or not query['state'][0] or on_callback is None):
                raise ValueError
    except (ValueError, TypeError, KeyError):
        return {'ok': False, 'state': 'failed', 'error_code': 'browser_input_invalid',
                'message': '本次浏览器登录参数或固定代理配置无效，请核对后重试'}
    if cancel.is_set():
        return {'ok': False, 'state': 'cancelled', 'error_code': 'cancelled', 'message': '操作已取消'}

    async def execute():
        from playwright.async_api import async_playwright
        async with async_playwright() as playwright:
            options = {'headless': False}
            if chrome_channel != 'chromium':
                options['channel'] = chrome_channel
            if proxy_config:
                options['proxy'] = proxy_config
            browser = await playwright.chromium.launch(**options)
            try:
                context = await browser.new_context()
                page = await context.new_page()
                page.set_default_timeout(4000)
                page.set_default_navigation_timeout(30000)
                captured = {}
                if action == 'oauth':
                    async def intercept(route):
                        url = route.request.url
                        if matches_callback(url, redirect_uri) and route.request.method == 'GET':
                            captured.setdefault('url', url)
                            await route.fulfill(status=200, content_type='text/html; charset=utf-8',
                                body='<html><body>授权回调已收到，请返回 Team48 查看结果。</body></html>')
                        else:
                            await route.abort()
                    await context.route(re.compile(r'^http://(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?/'), intercept)
                await _call(on_stage, 'browser_open', '正在打开官方登录窗口')
                await page.goto(authorize_url if action == 'oauth' else 'https://chatgpt.com/auth/login',
                                wait_until='domcontentloaded')
                return await _drive_page(page, action=action, email=email, password=password,
                    totp_secret=totp_secret, redirect_uri=redirect_uri, captured=captured,
                    on_stage=on_stage, on_callback=on_callback, on_mfa=on_mfa, guard=guard)
            finally:
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(browser.close(), timeout=10)

    flow = asyncio.create_task(execute(), name='team48-assisted-browser')
    stop = asyncio.create_task(cancel.wait(), name='team48-assisted-cancel')
    try:
        done, _ = await asyncio.wait({flow, stop}, timeout=float(timeout_seconds), return_when=asyncio.FIRST_COMPLETED)
        if flow in done:
            return await flow
        if guard['critical']:
            finished, _ = await asyncio.wait({flow}, timeout=CRITICAL_GRACE_SECONDS)
            if flow in finished:
                return await flow
        flow.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await flow
        if stop in done:
            return {'ok': False, 'state': 'cancelled', 'error_code': 'cancelled', 'message': '操作已取消，浏览器已关闭'}
        return {'ok': False, 'state': 'manual_required', 'error_code': 'browser_timeout',
                'message': '本次操作等待超时，浏览器已关闭；未自动重试，请核对官方状态'}
    except asyncio.CancelledError:
        flow.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await flow
        raise
    except Exception:
        return {'ok': False, 'state': 'failed', 'error_code': 'browser_failed',
                'message': '浏览器操作未完成，请确认 Chrome 已安装并在本机登录会话中运行'}
    finally:
        stop.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await stop
