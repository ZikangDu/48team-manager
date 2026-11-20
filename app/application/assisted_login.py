"""Explicit, ordinary-browser login; typed credentials live only in this process.

No account is created until a validated OAuth response is imported. The
``security`` and ``logout_all`` actions are user handoffs and never reported as
verified mutations. ``reset_totp`` is the one automated account-security change:
after sign-in it replaces the authenticator key through the official API inside
that browser session, keeping an encrypted recovery record at every step.
"""
from __future__ import annotations

import asyncio
import base64
import json
import secrets
from dataclasses import dataclass, field
from datetime import timedelta
from urllib.parse import urlsplit

import httpx
from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.application import credential_import, totp_backup, totp_reset
from app.application.jobs.browser import InvitedBrowserSession
from app.application.jobs.commands import command_runner
from app.application.oauth_sessions import OAuthSessionError, oauth_session_store
from app.application.operations import operation_store
from app.application.refresh_ownership import refresh_owner_kind
from app.application.tokens import decrypt_secret
from app.core.config import load_settings
from app.core.proxy import normalize_proxy_url
from app.core.time import as_utc, utcnow
from app.domain.automation import ACTIVE_STATES, DEFAULT_OAUTH_CLIENT_ID, OAUTH_REDIRECT_URI
from app.integrations.auth_bridge.credentials import CredentialImportError, normalize_email
from app.integrations.openai.chatgpt import chatgpt_client
from app.integrations.openai.mfa import ChatGPTMfaClient, normalize_totp_secret
from app.persistence.models.codex import CodexBinding
from app.persistence.models.identity import Account, Workspace
from app.persistence.models.oauth import OAuthSession
from app.persistence.models.operations import Operation
from app.persistence.models.quota import CredentialLease, QuotaProbeState

OPERATION_TYPE = "assisted_login"
ACTIONS = frozenset(("oauth", "security", "logout_all", "reset_totp"))
TOKEN_ENDPOINT = "https://auth.openai.com/oauth/token"
MAX_RESPONSE_BYTES = 1024 * 1024
BROWSER_TIMEOUT_SECONDS = 600
# Longer than the driver's own grace for a reset that has already started.
RESET_GRACE_SECONDS = 150
_start_lock = asyncio.Lock()

MESSAGES = {
    "challenge": "官方要求人机验证，请在浏览器窗口亲自完成；程序不会操作验证码",
    "email_verification": "官方要求邮箱验证码，请在浏览器窗口输入邮件中的验证码",
    "phone_verification": "官方要求手机验证，请在浏览器窗口亲自完成",
    "account_change": "页面进入注册或账号恢复，已停止自动填写，请人工核对",
    "consent": "密码和验证步骤后到达官方授权确认页，请在浏览器窗口核对并确认",
    "untrusted_origin": "页面离开预期官方来源，已停止自动填写，请人工核对",
    "ambiguous_otp": "验证码类型无法确定，请在浏览器窗口核对，未自动填写",
    "starting": "正在打开普通浏览器登录窗口",
    "browser_open": "正在打开官方登录窗口",
    "exchanging": "正在校验授权回调并保存凭据",
    "authenticated": "官方页面已显示登录状态，正在打开安全设置",
    "email": "正在填写本次账号邮箱",
    "password": "正在填写本次账号密码",
    "totp": "正在填写验证器验证码",
    "manual_required": "请在官方浏览器窗口完成验证或确认，程序不会绕过安全检查",
    "awaiting_user": "请在官方浏览器窗口完成操作；本机不会自动更换 2FA",
    "callback": "正在校验授权回调并保存凭据",
    "success": "授权已保存到本机，未检查额度或推送远端账号",
    "cancelled": "已停止本次浏览器任务；不会自动重放账号操作",
    "failed": "本次登录未完成，请核对官方页面后重新发起",
    "interrupted": "服务已重启或任务中断，请重新发起；没有自动重放登录",
    "mfa_session": "已登录官方页面，正在读取账号会话",
    "mfa_status": "正在读取官方 2FA 状态",
    "mfa_disable": "正在停用旧 2FA",
    "mfa_enroll": "正在生成新的 2FA 密钥",
    "mfa_activate": "新密钥已加密保存，正在激活",
    "mfa_confirm": "正在核对新 2FA 是否生效",
    "reset_login_incomplete": "没有登录到官方页面，未发送任何 2FA 更改；请核对后重新发起",
    "reset_interrupted": "换绑流程中断；请在「2FA 密钥」查询该邮箱的换绑状态，再重新发起核对",
    "authenticated_reset": "已登录官方页面，准备换绑 2FA",
}
DRIVER_ERRORS = {
    "browser_input_invalid": "浏览器登录参数或固定代理无效，请核对配置后重试",
    "browser_failed": "浏览器未能正常运行，请确认本机 Chrome 可用后重试",
    "browser_timeout": "本次浏览器操作已超时，未确认完成，请重新发起",
    "browser_closed": "浏览器窗口已关闭，未确认本次操作结果",
    "credentials_rejected": "官方未接受登录资料，已停止自动提交，请人工核对",
    "rate_limited": "官方提示操作频繁，已停止自动提交，请稍后再试",
    "account_unavailable": "官方提示账号不可用，已停止自动提交，请人工核对",
    "callback_rejected": "授权回调未通过核对，未保存本次授权",
    "logout_scope_unverified": "当前窗口已回到登录页；全部会话是否退出仍需在官方页面核对",
}


class AssistedLoginError(ValueError):
    def __init__(self, code: str, message: str, status_code: int = 409):
        super().__init__(message)
        self.code, self.message, self.status_code = code, message, status_code


@dataclass(repr=False)
class _Control:
    email: str
    action: str
    password: str
    totp_secret: str
    proxy: str
    snapshot: dict
    slot: InvitedBrowserSession
    ticket: str = ""
    authorize_url: str = ""
    cancel: asyncio.Event = field(default_factory=asyncio.Event)
    callback_result: dict | None = None
    reset_result: dict | None = None
    # The sign-in code comes from the key of an open reset, so an accepted code proves that key.
    login_uses_candidate: bool = False


_controls: dict[str, _Control] = {}


def _failure(code: str, message: str, status: str = "failed") -> dict:
    return {"ok": False, "success": False, "status": status, "error_code": code,
            "message": message, "error": message}


def _inputs(email, password, totp_secret, action):
    try:
        email = normalize_email(email)
    except CredentialImportError:
        raise AssistedLoginError("email_invalid", "请输入有效邮箱", 400) from None
    if action not in ACTIONS:
        raise AssistedLoginError("action_invalid", "不支持此浏览器操作", 400)
    # An empty password means "use the one already stored for this account" (resolved after preflight).
    if not isinstance(password, str) or len(password) > 4096:
        raise AssistedLoginError("password_invalid", "请输入有效的账号密码", 400)
    if not isinstance(totp_secret, str) or len(totp_secret) > 256:
        raise AssistedLoginError("totp_invalid", "2FA 密钥格式不正确", 400)
    secret = "".join(totp_secret.split()).upper()
    if secret:
        try:
            if not 16 <= len(secret) <= 128 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in secret):
                raise ValueError()
            if len(base64.b32decode(secret + "=" * (-len(secret) % 8))) < 10:
                raise ValueError()
        except (ValueError, TypeError):
            raise AssistedLoginError("totp_invalid", "请输入验证器密钥，或留空后在浏览器中手动验证", 400) from None
    return email, password, secret, action


def _proxy(value):
    try:
        result = normalize_proxy_url(value) or ""
        if result:
            parsed = urlsplit(result)
            if not parsed.hostname or parsed.port is None or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                raise ValueError()
        return result
    except (ValueError, TypeError):
        raise AssistedLoginError("proxy_invalid", "账号代理配置无效，请先核对代理设置") from None


async def _preflight(db, email, action):
    # SQLite writer reservation serializes with other credential/ownership updates.
    await db.execute(update(Account).where(Account.id == -1).values(version=Account.version))
    account = await db.scalar(select(Account).where(func.lower(Account.email) == email).execution_options(populate_existing=True))
    if account and (account.local_purpose == "disabled" or account.operational_state in {"disabled", "archived"}):
        raise AssistedLoginError("account_disabled", "账号已停用或归档，请先核对")
    # A 2FA reset neither reads nor replaces stored authorization, so remote refresh ownership is irrelevant to it.
    if action != "reset_totp" and account and await refresh_owner_kind(db, account.id) is not None:
        raise AssistedLoginError("remote_refresh_owned", "账号凭据由远端托管，请先完成刷新权交接")
    matches = [func.lower(Operation.email) == email]
    oauth_matches = [func.lower(OAuthSession.email) == email]
    if account:
        matches.append(Operation.account_id == account.id)
        oauth_matches.append(OAuthSession.account_id == account.id)
    if await db.scalar(select(Operation.id).where(Operation.state.in_(("pending", *ACTIVE_STATES)), or_(*matches)).limit(1)):
        raise AssistedLoginError("account_busy", "账号有进行中的任务，请先完成或取消")
    if await operation_store.browser_busy(db) is not None:
        raise AssistedLoginError("browser_busy", "已有浏览器任务，请先完成或取消")
    stamp = utcnow()
    if await db.scalar(select(OAuthSession.id).where(or_(*oauth_matches), OAuthSession.status.in_(("waiting", "exchanging")), OAuthSession.expires_at > stamp).limit(1)):
        raise AssistedLoginError("oauth_busy", "账号有未完成授权，请先完成或取消")
    if account:
        lease = await db.get(CredentialLease, account.id)
        codex = await db.get(CodexBinding, account.id)
        if (lease and lease.token and (lease.expires_at is None or as_utc(lease.expires_at) > stamp)) or (codex and codex.lease_until and as_utc(codex.lease_until) > stamp):
            raise AssistedLoginError("account_busy", "账号正在刷新或检测，请稍后再试")
        if await db.scalar(select(QuotaProbeState.context_key).where(QuotaProbeState.account_id == account.id, QuotaProbeState.lease_expires_at > stamp).limit(1)):
            raise AssistedLoginError("account_busy", "账号正在检查额度，请稍后再试")
    return account


async def _exchange_code(*, code, client_id, redirect_uri, code_verifier, proxy="", transport=None):
    body = {"grant_type": "authorization_code", "client_id": client_id, "code": code,
            "redirect_uri": redirect_uri, "code_verifier": code_verifier}
    buffer = bytearray()
    try:
        async with asyncio.timeout(40):
            async with httpx.AsyncClient(trust_env=False, follow_redirects=False, proxy=proxy or None,
                    transport=transport, timeout=httpx.Timeout(35, connect=10)) as client:
                async with client.stream("POST", TOKEN_ENDPOINT, json=body, headers={"Accept": "application/json"}) as response:
                    if response.status_code != 200:
                        raise AssistedLoginError("oauth_exchange_failed", "官方授权换票未完成，请重新发起授权", 502)
                    length = response.headers.get("content-length")
                    if length and (not length.isdigit() or int(length) > MAX_RESPONSE_BYTES):
                        raise AssistedLoginError("oauth_response_invalid", "官方授权响应格式异常", 502)
                    async for chunk in response.aiter_bytes():
                        if len(buffer) + len(chunk) > MAX_RESPONSE_BYTES:
                            raise AssistedLoginError("oauth_response_invalid", "官方授权响应过大", 502)
                        buffer.extend(chunk)
                    payload = json.loads(buffer)
        if not isinstance(payload, dict) or not isinstance(payload.get("access_token"), str) or not payload["access_token"]:
            raise AssistedLoginError("oauth_response_invalid", "官方未返回有效授权凭据", 502)
        return {key: payload[key] for key in ("access_token", "refresh_token", "id_token") if key in payload}
    except AssistedLoginError:
        raise
    except Exception:
        raise AssistedLoginError("oauth_exchange_failed", "官方授权换票未完成，请核对网络后重新发起", 502) from None
    finally:
        body.clear()
        buffer.clear()


async def _saved_totp(db, email, account):
    """Key already kept on this machine for the email: its 2FA backup, else a stored owner 2FA."""
    secret = await totp_backup.stored_secret(db, email)
    if secret or account is None:
        return secret
    rows = await db.scalars(select(Workspace).where(Workspace.owner_account_id == account.id).order_by(Workspace.id))
    for workspace in rows:
        try:
            return normalize_totp_secret(decrypt_secret(workspace.owner_totp_secret_encrypted))
        except ValueError:
            continue
    return ""


async def credential_hints(db, *, email):
    """What this machine already holds for an email, as booleans only (never a value)."""
    try:
        email = normalize_email(email)
    except CredentialImportError:
        raise AssistedLoginError("email_invalid", "请输入有效邮箱", 400) from None
    account = await db.scalar(select(Account).where(func.lower(Account.email) == email))
    try:
        pending = await totp_reset.open_reset(db, email)
        phase = pending["phase"] if pending else "none"
    except CredentialImportError:
        pending, phase = None, "unreadable"
    candidate = bool(pending and pending["phase"] in ("activating", "activated"))
    return {"ok": True, "email": email, "known": account is not None,
            "has_password": bool(account is not None and decrypt_secret(account.password_encrypted)),
            "has_totp": candidate or bool(await _saved_totp(db, email, account)),
            "reset_phase": phase}


async def start_assisted_login(db, *, email, password="", totp_secret="", action="oauth", confirm_reset=False):
    slot = None
    control = None
    public_id = None
    mode = ""
    try:
        email, password, totp_secret, action = _inputs(email, password, totp_secret, action)
        if action == "reset_totp" and confirm_reset is not True:
            raise AssistedLoginError("reset_confirmation_required", "请先确认要更换此账号的 2FA；旧验证器会随之失效", 400)
        if not command_runner.ready:
            raise AssistedLoginError("runner_unavailable", "后台执行器尚未就绪，请稍后重试", 503)
        async with _start_lock:
            slot = InvitedBrowserSession()
            if not await slot.try_reserve():
                raise AssistedLoginError("browser_busy", "已有浏览器任务，请先完成或取消")
            account = await _preflight(db, email, action)
            if not password:
                password = decrypt_secret(account.password_encrypted) if account else ""
                if not password:
                    raise AssistedLoginError("password_required", "请输入账号密码；本机没有保存这个账号的密码", 400)
            try:
                pending = await totp_reset.open_reset(db, email)
            except CredentialImportError:
                # An unreadable recovery record may hold the only copy of a live key: never reset over it.
                if action == "reset_totp":
                    raise
                pending = None
            candidate = pending["secret"] if pending and pending["phase"] in ("activating", "activated") else ""
            uses_candidate = False
            if action == "reset_totp":
                mode = "resume" if pending else "fresh"
                if candidate:
                    # Once an activation may have landed, only the new key can pass a 2FA prompt.
                    totp_secret, uses_candidate = candidate, True
            if not totp_secret:
                totp_secret = candidate or await _saved_totp(db, email, account)
            candidate = ""
            snapshot = await credential_import.account_snapshot(db, email) or {"id": None}
            control = _Control(email, action, password, totp_secret, _proxy(account.proxy if account else ""), snapshot, slot)
            control.login_uses_candidate = uses_candidate
            operation = await operation_store.create(db, op_type=OPERATION_TYPE, account_id=account.id if account else None,
                email=email, source="manual", input_payload={"action": action, **({"mode": mode} if mode else {})})
            public_id = operation.public_id
            if action == "oauth":
                auth = chatgpt_client.create_oauth_authorize_url(client_id=DEFAULT_OAUTH_CLIENT_ID,
                    redirect_uri=OAUTH_REDIRECT_URI, login_hint=email)
                control.ticket = secrets.token_urlsafe(24)
                control.authorize_url = auth["authorize_url"]
                memory = {**auth, "ticket": control.ticket, "email": email, "mode": "manual",
                          "job_id": public_id, "redirect_uri": OAUTH_REDIRECT_URI,
                          "proxy": control.proxy, "expires_at": utcnow() + timedelta(minutes=12)}
                await oauth_session_store.persist(db, memory, purpose=OPERATION_TYPE,
                    account_id=account.id if account else None,
                    credential_revision=int(account.credential_revision or 1) if account else None)
                memory.clear()
                auth.clear()
            await operation_store.note(db, operation, "starting", MESSAGES["starting"])
            await db.commit()
            _controls[public_id] = control
            command_runner.spawn(public_id, lambda session: _run(session, public_id, control))
        return {"ok": True, "success": True, "operation_id": public_id, "status": "running", "email": email, "action": action,
                "message": MESSAGES["starting"], **({"mode": mode} if mode else {})}
    except (AssistedLoginError, CredentialImportError) as exc:
        await db.rollback()
        return _failure(exc.code, exc.message)
    except Exception:
        await db.rollback()
        return _failure("start_failed", "无法启动本次浏览器任务，请刷新后重试")
    finally:
        if public_id not in command_runner.running_ids():
            if public_id:
                _controls.pop(public_id, None)
                row = await operation_store.get_by_public_id(db, public_id)
                if row and row.state in ACTIVE_STATES:
                    await operation_store.finish(db, row, _failure("start_failed", "浏览器任务未能启动"))
                    await _finish_oauth(db, control, success=False)
                    await db.commit()
            if control:
                _scrub(control)
            if slot:
                await slot.close()


def _scrub(control):
    control.password = control.totp_secret = control.proxy = control.authorize_url = ""
    control.snapshot.clear()


async def _finish_oauth(db, control, *, success):
    if control and control.ticket:
        row = await db.scalar(select(OAuthSession).where(OAuthSession.public_id == control.ticket))
        if row and row.status in {"waiting", "exchanging"}:
            await oauth_session_store.finish(db, row, success=success)


async def _complete(db, public_id, control, callback_url):
    if control.cancel.is_set():
        return _failure("cancelled", MESSAGES["cancelled"], "cancelled")
    if control.callback_result is not None:
        return control.callback_result
    draft_id = None
    payload = None
    context = {}
    parsed = {}
    try:
        stored, parsed = await oauth_session_store.begin_exchange(db, control.ticket, callback_url, purpose=OPERATION_TYPE)
        context = oauth_session_store.exchange_context(stored)
        if context["proxy"] != control.proxy:
            raise AssistedLoginError("proxy_changed", "本次授权代理已变化，请重新发起")
        # begin_exchange claims the one-use session and commits. Explicitly
        # release any later ORM transaction before waiting on remote I/O.
        await db.commit()
        payload = await _exchange_code(code=parsed["code"], client_id=context["client_id"],
            redirect_uri=context["redirect_uri"], code_verifier=context["code_verifier"], proxy=control.proxy)
        context.clear()
        parsed.clear()
        if control.cancel.is_set():
            raise AssistedLoginError("cancelled", MESSAGES["cancelled"])
        operation = await operation_store.get_by_public_id(db, public_id)
        if operation is None or operation.state not in ACTIVE_STATES or operation.cancel_requested:
            raise AssistedLoginError("cancelled", MESSAGES["cancelled"])
        # Consume this session in the same transaction as import, so it cannot
        # block itself. All other OAuth/operation/refresh locks remain active.
        await oauth_session_store.finish(db, stored, success=True)
        preview = await credential_import.preview_import(db, payload, expected_email=control.email,
            expected_account=control.snapshot, ignore_operation_id=operation.id)
        draft_id = preview.get("draft_id")
        candidates = preview.get("candidates", [])
        if len(candidates) != 1 or candidates[0].get("allowed") is not True or preview.get("errors"):
            raise AssistedLoginError("identity_conflict", "授权身份、工作区或账号状态未能唯一确认，未保存凭据")
        saved = await credential_import.commit_import(db, draft_id, [candidates[0]["id"]], verify_quota=False)
        result = {"ok": True, "success": True, "status": "success", "message": MESSAGES["success"],
                  "account_id": saved["imported"][0]["account_id"], "verification": "pending"}
        control.callback_result = result
        return result
    except (AssistedLoginError, OAuthSessionError, CredentialImportError):
        await db.rollback()
        await _finish_oauth(db, control, success=False)
        await db.commit()
        result = _failure("authorization_not_saved", "授权未保存，可能存在身份冲突、账号变化或回调失效；请重新核对", "manual_required")
        control.callback_result = result
        return result
    except Exception:
        await db.rollback()
        await _finish_oauth(db, control, success=False)
        await db.commit()
        result = _failure("authorization_not_saved", "授权结果未能完整确认，请查看本地账号后重新发起", "manual_required")
        control.callback_result = result
        return result
    finally:
        context.clear()
        parsed.clear()
        if draft_id:
            try:
                credential_import.discard_preview(draft_id)
            except CredentialImportError:
                pass
        if payload:
            payload.clear()


async def _reset(db, public_id, control, transport, proof):
    """Called by the driver once the page is signed in; the window stays open until this returns."""
    if control.reset_result is not None:
        return control.reset_result
    client = ChatGPTMfaClient(transport, expected_email=control.email)

    async def report(stage_name):
        row = await operation_store.get_by_public_id(db, public_id)
        if row is not None and row.state in ACTIVE_STATES:
            await operation_store.note(db, row, stage_name, MESSAGES[stage_name])
            await db.commit()

    try:
        accepted = isinstance(proof, dict) and proof.get("totp_accepted") is True
        result = await totp_reset.run_reset(db, email=control.email, client=client, operation_id=public_id,
            login_proof=control.login_uses_candidate and accepted, report=report,
            should_abort=control.cancel.is_set)
    except Exception:
        await db.rollback()
        result = _failure("reset_interrupted", MESSAGES["reset_interrupted"], "manual_required")
    control.reset_result = result
    return result


async def _run(db, public_id, control):
    monitor = None
    done = asyncio.Event()
    try:
        from app.integrations.openai.browser.assisted_login import run_assisted_browser
        factory = async_sessionmaker(db.bind, expire_on_commit=False)

        async def watch():
            ticks = 0
            while not done.is_set():
                try:
                    await asyncio.wait_for(done.wait(), timeout=1)
                    return
                except asyncio.TimeoutError:
                    pass
                async with factory() as probe:
                    row = await operation_store.get_by_public_id(probe, public_id)
                    if row is None or row.state not in ACTIVE_STATES or row.cancel_requested:
                        control.cancel.set()
                    ticks += 1
                    if row is not None and ticks % 20 == 0:
                        await operation_store.heartbeat(probe, row)
                        await probe.commit()

        async def stage(stage_name, _untrusted_message=""):
            key = stage_name if stage_name in MESSAGES or stage_name in DRIVER_ERRORS else "manual_required"
            if key == "authenticated" and control.action == "reset_totp":
                key = "authenticated_reset"
            row = await operation_store.get_by_public_id(db, public_id)
            if row is not None and row.state in ACTIVE_STATES:
                await operation_store.note(db, row, key, MESSAGES.get(key) or DRIVER_ERRORS[key])
                await db.commit()

        monitor = asyncio.create_task(watch())
        await db.commit()
        on_mfa = (lambda transport, proof: _reset(db, public_id, control, transport, proof)) if control.action == "reset_totp" else None
        async with asyncio.timeout(BROWSER_TIMEOUT_SECONDS + RESET_GRACE_SECONDS):
            result = await run_assisted_browser(email=control.email, password=control.password,
                totp_secret=control.totp_secret, authorize_url=control.authorize_url,
                redirect_uri=OAUTH_REDIRECT_URI, action=control.action, cancel=control.cancel,
                on_stage=stage, on_callback=lambda url: _complete(db, public_id, control, url), on_mfa=on_mfa,
                chrome_channel=load_settings().browser_channel or "chrome", proxy=control.proxy,
                timeout_seconds=BROWSER_TIMEOUT_SECONDS)
        if control.reset_result is not None:
            # Whatever happened to the window afterwards, the reset's own outcome is the truth.
            return dict(control.reset_result)
        if control.callback_result and control.callback_result.get("success"):
            return dict(control.callback_result)
        if control.cancel.is_set() or isinstance(result, dict) and (result.get("status") == "cancelled" or result.get("state") == "cancelled"):
            return _failure("cancelled", MESSAGES["cancelled"], "cancelled")
        if control.callback_result:
            return dict(control.callback_result)
        code = result.get("error_code") if isinstance(result, dict) else None
        if code in DRIVER_ERRORS:
            terminal = "failed" if code in {"browser_input_invalid", "browser_failed"} else "manual_required"
            return _failure(code, DRIVER_ERRORS[code], terminal)
        if control.action in {"security", "logout_all"}:
            return _failure("official_review_required", "官方安全设置已交给你操作；本机未确认退出会话或更换 2FA", "manual_required")
        if control.action == "reset_totp":
            return _failure("browser_login_incomplete", MESSAGES["reset_login_incomplete"], "manual_required")
        return _failure("browser_login_incomplete", MESSAGES["failed"], "manual_required")
    except asyncio.CancelledError:
        control.cancel.set()
        if control.reset_result is not None:
            return dict(control.reset_result)
        if control.callback_result and control.callback_result.get("success"):
            return dict(control.callback_result)
        if control.action == "reset_totp":
            return _failure("interrupted", MESSAGES["reset_interrupted"], "manual_required")
        return _failure("interrupted", MESSAGES["interrupted"], "manual_required")
    except Exception:
        if control.reset_result is not None:
            return dict(control.reset_result)
        if control.action == "reset_totp":
            return _failure("reset_interrupted", MESSAGES["reset_interrupted"], "manual_required")
        return _failure("browser_login_incomplete", MESSAGES["failed"], "manual_required")
    finally:
        done.set()
        if monitor:
            await asyncio.gather(monitor, return_exceptions=True)
        try:
            await db.rollback()
            await _finish_oauth(db, control, success=False)
            await db.commit()
            # CommandRunner retains this same ORM object across our command.
            # Rollback expires it; reload before its synchronous attributes are
            # read by OperationStore.finish in the runner.
            await db.scalar(select(Operation).where(Operation.public_id == public_id).execution_options(populate_existing=True))
        finally:
            _scrub(control)
            _controls.pop(public_id, None)
            await control.slot.close()


async def status_assisted_login(db, operation_id):
    row = await operation_store.get_by_public_id(db, str(operation_id))
    if row is None or row.op_type != OPERATION_TYPE:
        return _failure("not_found", "浏览器任务不存在")
    try:
        inputs = json.loads(row.input_json or "{}")
        result = json.loads(row.result_json or "{}")
    except (ValueError, TypeError):
        inputs, result = {}, {}
    allowed = {"ok", "success", "status", "error_code", "message", "error", "account_id", "verification",
               "phase", "backup_saved", "owner_synced", "extra_factors", "step", "remote_status", "remote_code"}
    public = {key: value for key, value in result.items() if key in allowed} if isinstance(result, dict) else {}
    stage = row.current_step or "starting"
    # Stage names this task went through, in order; names only (their texts are fixed and local).
    stages = []
    try:
        history = json.loads(row.log_json or "[]")
    except (ValueError, TypeError):
        history = []
    for item in history if isinstance(history, list) else ():
        name = item.get("stage") if isinstance(item, dict) else None
        if isinstance(name, str) and (name in MESSAGES or name in DRIVER_ERRORS) and (not stages or stages[-1] != name):
            stages.append(name)
    return {"ok": True, "operation_id": row.public_id, "state": row.state, "status": row.state, "stages": stages[-40:],
            "stage": stage, "message": public.get("message") or MESSAGES.get(stage) or DRIVER_ERRORS.get(stage) or MESSAGES["manual_required"],
            "result": public, "email": row.email, "action": inputs.get("action") if isinstance(inputs, dict) else None,
            "mode": inputs.get("mode") if isinstance(inputs, dict) and inputs.get("mode") in ("fresh", "resume") else None,
            "cancel_requested": bool(row.cancel_requested)}


async def cancel_assisted_login(db, operation_id):
    row = await operation_store.get_by_public_id(db, str(operation_id))
    if row is None or row.op_type != OPERATION_TYPE:
        return _failure("not_found", "浏览器任务不存在")
    if row.state not in ACTIVE_STATES:
        return {"ok": True, "operation_id": row.public_id, "status": row.state, "message": "任务已结束"}
    row.cancel_requested = True
    await db.commit()
    if row.public_id in _controls:
        _controls[row.public_id].cancel.set()
    return {"ok": True, "operation_id": row.public_id, "status": "cancelling", "message": "已请求停止本次浏览器任务"}


async def cleanup_assisted_logins():
    controls = list(_controls.values())
    _controls.clear()
    for control in controls:
        control.cancel.set()
        _scrub(control)
        await control.slot.close()


async def recover_assisted_logins(db):
    rows = list(await db.scalars(select(Operation).where(Operation.op_type == OPERATION_TYPE, Operation.state.in_(("pending", *ACTIVE_STATES)))))
    for row in rows:
        await operation_store.finish(db, row, _failure("interrupted", MESSAGES["interrupted"], "manual_required"))
    sessions = list(await db.scalars(select(OAuthSession).where(OAuthSession.purpose == OPERATION_TYPE, OAuthSession.status.in_(("waiting", "exchanging")))))
    for stored in sessions:
        await oauth_session_store.finish(db, stored, success=False)
    await db.commit()
    return {"recovered": len(rows), "expired_authorizations": len(sessions)}
