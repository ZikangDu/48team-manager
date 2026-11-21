"""Browser-free account auth through the local GPTAuthBridge.

Two operations, both running in the background with a durable Operation record:

* batch login — log many accounts in by protocol (the Bridge fans them out up to
  its own concurrency) and import each account's credentials locally.
* reset 2FA — obtain one account's web session by protocol, then run the native
  durable reset (app/application/totp_reset.py) over it with no browser.

Typed passwords and TOTP keys live only inside the running task; the Bridge is on
127.0.0.1 only; its raw responses never become API responses or logs.
"""
from __future__ import annotations

import asyncio
import json

from sqlalchemy import func, select

from app.application import credential_import, totp_backup, totp_reset
from app.application.jobs.commands import command_runner
from app.application.operations import operation_store
from app.application.refresh_ownership import refresh_owner_kind
from app.application.tokens import decrypt_secret
from app.application.managed_auth import AuthRouteError, resolve_auth_route
from app.core.config import load_settings
from app.core.proxy import normalize_proxy_url
from app.domain.automation import ACTIVE_STATES
from app.integrations.auth_bridge.credentials import CredentialImportError, normalize_email
from app.integrations.auth_bridge.login_client import BridgeError, BridgeLoginClient
from app.integrations.openai.mfa import normalize_totp_secret
from app.integrations.openai.mfa_http import protocol_mfa_client
from app.persistence.models.identity import Account, Workspace
from app.persistence.models.operations import Operation

LOGIN_OP = "protocol_login"
RESET_OP = "protocol_reset"
MAX_LINES = 50

MESSAGES = {
    "bridge_unavailable": "无法连接本机授权桥，请先启动 GPTAuthBridge",
    "bridge_starting": "授权桥正在启动（首次启动约需十几秒），请稍后重试",
    "bridge_incompatible": "本机服务不是兼容版本的 GPTAuthBridge",
    "bridge_busy": "授权桥繁忙，请稍后重试",
    "bridge_timeout": "授权桥请求超时；未重放登录，请核对后重试",
    "bridge_credentials_rejected": "登录凭据未通过验证，请核对密码和 2FA 密钥",
    "bridge_email_verification": "官方要求邮箱验证码，请改用浏览器辅助登录",
    "bridge_account_unavailable": "官方报告账号不可用，请人工核对",
    "bridge_validation_failed": "官方登录验证未完成，请稍后重试或改用浏览器辅助登录",
    "bridge_login_failed": "协议登录未取得可用凭据，请核对密码和 2FA 密钥",
    "bridge_session_missing": "协议登录未返回可用会话，请改用浏览器辅助登录",
    "mfa_session": "已登录官方会话，正在读取 2FA 状态",
    "mfa_status": "正在读取官方 2FA 状态",
    "mfa_disable": "正在停用旧 2FA",
    "mfa_enroll": "正在生成新的 2FA 密钥",
    "mfa_activate": "新密钥已加密保存，正在激活",
    "mfa_confirm": "正在核对新 2FA 是否生效",
    "protocol_login": "正在通过协议登录账号",
    "import": "正在导入授权凭据",
}


class ProtocolAuthError(ValueError):
    def __init__(self, code: str, message: str, status_code: int = 409):
        super().__init__(message)
        self.code, self.message, self.status_code = code, message, status_code


def _bridge() -> BridgeLoginClient:
    settings = load_settings()
    if not settings.auth_bridge_enabled:
        raise ProtocolAuthError("bridge_disabled", "未启用授权桥，请在设置中开启 GPTAuthBridge", 409)
    if settings.auth_bridge_managed:
        from app.integrations.auth_bridge.supervisor import bridge_supervisor

        if bridge_supervisor.state == "starting":
            raise ProtocolAuthError("bridge_starting", MESSAGES["bridge_starting"], 503)
        if bridge_supervisor.state == "failed":
            raise ProtocolAuthError("bridge_unavailable", bridge_supervisor.reason or MESSAGES["bridge_unavailable"], 503)
    try:
        return BridgeLoginClient(settings.auth_bridge_url)
    except BridgeError as exc:
        raise ProtocolAuthError(exc.code, exc.message, exc.status_code) from None


def _default_proxy() -> str:
    try:
        return normalize_proxy_url(load_settings().auth_bridge_proxy) or ""
    except (ValueError, TypeError):
        return ""


async def _account_proxy(db, email: str) -> str:
    account = await db.scalar(select(Account).where(func.lower(Account.email) == email))
    if account is not None and account.proxy:
        try:
            return normalize_proxy_url(account.proxy) or _default_proxy()
        except (ValueError, TypeError):
            return _default_proxy()
    return _default_proxy()


def parse_account_lines(text: str) -> list[dict]:
    """Parse 'email----password----2FA' / 'email|password|2FA' lines (2FA optional)."""
    if not isinstance(text, str) or len(text) > 200_000:
        raise ProtocolAuthError("input_invalid", "输入格式不正确", 400)
    accounts: list[dict] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = _split_line(line)
        if parts is None:
            raise ProtocolAuthError("line_invalid", f"无法解析账号行：{line[:40]}", 400)
        email, password, totp = parts
        try:
            email = normalize_email(email)
        except CredentialImportError:
            raise ProtocolAuthError("line_invalid", f"邮箱格式不正确：{email[:40]}", 400) from None
        if not password:
            raise ProtocolAuthError("line_invalid", f"缺少密码：{email}", 400)
        if totp:
            try:
                totp = normalize_totp_secret(totp)
            except ValueError:
                raise ProtocolAuthError("line_invalid", f"2FA 密钥格式不正确：{email}", 400) from None
        if email in seen:
            raise ProtocolAuthError("line_duplicate", f"账号重复：{email}", 400)
        seen.add(email)
        accounts.append({"email": email, "password": password, "totp": totp})
        if len(accounts) > MAX_LINES:
            raise ProtocolAuthError("too_many", f"单次最多 {MAX_LINES} 个账号", 400)
    if not accounts:
        raise ProtocolAuthError("input_empty", "请至少输入一个账号", 400)
    return accounts


def _split_line(line: str) -> tuple[str, str, str] | None:
    """Split 'email----password----2FA' / '——' / '|'. The 2FA part is optional.

    A run of dashes is one delimiter; a password may itself contain '--', so the
    delimiter width is the shorter of the two surrounding runs (as gpt-auth-bridge
    does). An empty password means this was really a two-part line.
    """
    import re
    host = r"@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+?[a-z0-9]+"
    three = re.match(rf"^(.+?{host})\s*(-{{2,}})(.*?)(-{{2,}})((?:[^-\r\n]|-(?!-))*)$", line, re.I)
    if three and three.group(5).strip():
        email, left, middle, right, secret = three.groups()
        width = min(4, len(left), len(right))
        password = (left[width:] + middle + right[width:]).strip()
        if password:
            return email.strip(), password, secret.strip()
    other = re.match(rf"^(.+?{host})\s*(?:—{{2,}}|\|)(.+?)(?:—{{2,}}|\|)(.*)$", line, re.I)
    if other and other.group(2).strip():
        return other.group(1).strip(), other.group(2).strip(), other.group(3).strip()
    two = re.match(rf"^(.+?{host})\s*(?:-{{2,}}|—{{2,}}|\|)(.+)$", line, re.I)
    if two:
        password = two.group(2).strip()
        if password and password.strip("-—"):   # a run of only dashes is not a password
            return two.group(1).strip(), password, ""
    return None


# ---------------------------------------------------------------- batch login

async def start_batch_login(db, *, text, proxy=None, concurrency=None, proxy_mode="auto", workspace_id=None,
                            proxy_profile_id=None):
    accounts = parse_account_lines(text)
    if not command_runner.ready:
        raise ProtocolAuthError("runner_unavailable", "后台执行器尚未就绪，请稍后重试", 503)
    client = _bridge()
    try:
        await client.status()
    except BridgeError as exc:
        raise ProtocolAuthError(exc.code, MESSAGES.get(exc.code, exc.message), exc.status_code) from None
    settings = load_settings()
    # Keep legacy callers with an explicit URL compatible, while the UI defaults
    # to resolving each account's own / mother-account exit independently.
    if proxy is not None and proxy_mode == "auto":
        proxy_mode = "custom" if proxy else "direct"
    for item in accounts:
        try:
            item["route"] = await resolve_auth_route(db, item["email"], mode=proxy_mode, workspace_id=workspace_id,
                                                      proxy=proxy, profile_id=proxy_profile_id)
        except AuthRouteError as exc:
            item["route_error"] = {"code": exc.code, "message": exc.message}
    limit = int(concurrency or settings.auth_bridge_concurrency or 5)
    limit = max(1, min(10, limit))
    operation = await operation_store.create(db, op_type=LOGIN_OP, source="manual",
        input_payload={"count": len(accounts), "concurrency": limit})
    public_id = operation.public_id
    await operation_store.note(db, operation, "protocol_login", f"协议批量登录：{len(accounts)} 个账号，并发 {limit}")
    await db.commit()
    payload = [dict(item) for item in accounts]
    command_runner.spawn(public_id, lambda session: _run_batch(session, public_id, payload, "", limit))
    return {"ok": True, "operation_id": public_id, "status": "running", "count": len(accounts), "concurrency": limit,
            "message": f"已开始协议登录 {len(accounts)} 个账号"}


async def _run_batch(db, public_id, accounts, proxy, concurrency):
    try:
        client = _bridge()
        groups, rows, routes = {}, [], {}
        for index, item in enumerate(accounts):
            if item.get("route_error"):
                rows.append({"email": item["email"], "ok": False, **item["route_error"]})
                continue
            route = item.get("route")
            routes[item["email"]] = route
            groups.setdefault(route.proxy if route else proxy, []).append({"id": f"a{index}", "email": item["email"],
                "openai_password": item["password"], "two_factor_secret": item["totp"]})
        for exit_url, wire in groups.items():
            try:
                rows.extend(await client.login_batch(wire, proxy=exit_url, concurrency=concurrency, workspace_mode="all"))
            except BridgeError as exc:
                rows.extend({"email": item["email"], "ok": False, "code": exc.code} for item in wire)
            finally:
                for item in wire:
                    item.clear()
        results = []
        imported = 0
        operation = await operation_store.get_by_public_id(db, public_id)
        for row in rows:
            email = row["email"]
            entry = {"email": email, "login": "ok" if row["ok"] else "failed", "code": row["code"]}
            if row.get("message"):
                entry["message"] = row["message"]
            if row["ok"] and row.get("account"):
                try:
                    entry["import"] = await _import_account(db, email, row["account"], operation=operation,
                                                           auth_route=routes.get(email))
                    if entry["import"] == "imported":
                        imported += 1
                except CredentialImportError as exc:
                    entry.update({"import": "failed", "code": exc.code})
            results.append(entry)
            row.clear()
        ok = sum(1 for item in results if item["login"] == "ok")
        return {"ok": True, "success": True, "status": "success",
                "message": f"登录成功 {ok}/{len(results)}，导入 {imported}",
                "login_success": ok, "imported": imported, "total": len(results), "results": results}
    except ProtocolAuthError as exc:
        return {"success": False, "status": "failed", "error_code": exc.code,
                "error": MESSAGES.get(exc.code, exc.message)}
    except BridgeError as exc:
        return {"success": False, "status": "failed", "error_code": exc.code,
                "error": MESSAGES.get(exc.code, exc.message)}
    except Exception:
        return {"success": False, "status": "failed", "error_code": "protocol_login_failed",
                "error": "协议批量登录未完成，请核对授权桥与任务记录"}
    finally:
        for item in accounts:
            item.clear()


async def _import_account(db, email: str, account: dict, *, operation: Operation | None = None, auth_route=None) -> str:
    """Prefer the managed workspace credential, retaining remote refresh ownership."""
    existing = await db.scalar(select(Account).where(func.lower(Account.email) == email))
    if existing is not None and await refresh_owner_kind(db, existing.id) is not None:
        return "skipped_remote_owned"
    content = {"email": email}
    for src, dst in (("openai_access_token", "access_token"), ("openai_rt", "refresh_token"),
                     ("openai_id_token", "id_token"), ("openai_account_id", "account_id")):
        if account.get(src):
            content[dst] = account[src]
    desired = existing.official_account_id if existing else None
    if not desired and auth_route and auth_route.workspace_id:
        team = await db.get(Workspace, auth_route.workspace_id)
        desired = team.official_workspace_id if team else None
    workspaces = account.get("business_workspace_credentials") or []
    matching = [item for item in workspaces if desired and desired in {item.get("workspaceId"), item.get("accountId")}]
    if matching or not content.get("access_token"):
        # No personal credential; fall back to the first business workspace.
        if not workspaces:
            return "no_credential"
        if not matching and len(workspaces) > 1:
            return "workspace_selection_required"
        first = matching[0] if matching else workspaces[0]
        content.update(access_token=first.get("accessToken"), refresh_token=first.get("refreshToken"),
                       id_token=first.get("idToken"), account_id=first.get("accountId"))
    if operation is not None and operation.state in ACTIVE_STATES and operation.current_step != "import":
        await operation_store.note(db, operation, "import", MESSAGES["import"])
        await db.commit()
    preview = await credential_import.preview_import(db, content, expected_email=email)
    candidates = [item for item in preview.get("candidates", []) if item.get("allowed") is True]
    if not candidates or preview.get("errors"):
        draft = preview.get("draft_id")
        if draft:
            try:
                credential_import.discard_preview(draft)
            except CredentialImportError:
                pass
        return "conflict"
    saved = await credential_import.commit_import(db, preview["draft_id"], [candidates[0]["id"]], verify_quota=False,
                                                  auth_route=auth_route, manage_after_import=True)
    return "imported" if saved.get("imported") else "conflict"


# ---------------------------------------------------------------- reset 2FA

async def start_protocol_reset(db, *, email, password="", totp_secret="", confirm_reset=False, proxy=None):
    email = normalize_email(email)
    if confirm_reset is not True:
        raise ProtocolAuthError("reset_confirmation_required", "请先确认要更换此账号的 2FA；旧验证器会随之失效", 400)
    if not command_runner.ready:
        raise ProtocolAuthError("runner_unavailable", "后台执行器尚未就绪，请稍后重试", 503)
    client = _bridge()
    try:
        await client.status()
    except BridgeError as exc:
        raise ProtocolAuthError(exc.code, MESSAGES.get(exc.code, exc.message), exc.status_code) from None
    account = await db.scalar(select(Account).where(func.lower(Account.email) == email))
    if account is not None and account.operational_state in {"disabled", "archived"}:
        raise ProtocolAuthError("account_disabled", "账号已停用或归档，请先核对", 409)
    if await _reset_busy(db, email):
        raise ProtocolAuthError("account_busy", "此账号有进行中的协议任务，请先完成或取消", 409)
    # Unreadable recovery record may hold the only copy of a live key; never reset over it.
    pending = await totp_reset.open_reset(db, email)
    candidate = pending["secret"] if pending and pending["phase"] in ("activating", "activated") else ""
    if not password:
        password = decrypt_secret(account.password_encrypted) if account else ""
        if not password:
            raise ProtocolAuthError("password_required", "请输入账号密码；本机没有保存这个账号的密码", 400)
    login_totp = candidate or (normalize_totp_secret(totp_secret) if totp_secret else "") or await _saved_totp(db, email, account)
    if not login_totp:
        raise ProtocolAuthError("totp_required", "请输入现有 2FA 密钥；协议登录需要它", 400)
    use_proxy = _account_proxy_sync(account) if proxy is None else (normalize_proxy_url(proxy) or "")
    operation = await operation_store.create(db, op_type=RESET_OP, account_id=account.id if account else None,
        email=email, source="manual", input_payload={"mode": "resume" if pending else "fresh"})
    public_id = operation.public_id
    await operation_store.note(db, operation, "protocol_login", MESSAGES["protocol_login"])
    await db.commit()
    command_runner.spawn(public_id, lambda session: _run_reset(
        session, public_id, email, password, login_totp, use_proxy, bool(candidate)))
    return {"ok": True, "operation_id": public_id, "status": "running", "email": email,
            "mode": "resume" if pending else "fresh", "message": "已开始协议重设 2FA"}


def _account_proxy_sync(account) -> str:
    if account is not None and account.proxy:
        try:
            return normalize_proxy_url(account.proxy) or _default_proxy()
        except (ValueError, TypeError):
            return _default_proxy()
    return _default_proxy()


async def _saved_totp(db, email, account) -> str:
    secret = await totp_backup.stored_secret(db, email)
    if secret or account is None:
        return secret
    for workspace in await db.scalars(select(Workspace).where(Workspace.owner_account_id == account.id).order_by(Workspace.id)):
        try:
            return normalize_totp_secret(decrypt_secret(workspace.owner_totp_secret_encrypted))
        except ValueError:
            continue
    return ""


async def _reset_busy(db, email) -> bool:
    found = await db.scalar(select(Operation.id).where(
        Operation.op_type.in_((RESET_OP, "assisted_login")),
        func.lower(Operation.email) == email,
        Operation.state.in_(("pending", *ACTIVE_STATES))).limit(1))
    return found is not None


async def _run_reset(db, public_id, email, password, login_totp, proxy, uses_candidate):
    control = {"cancelled": False}

    async def watch():
        from sqlalchemy.ext.asyncio import async_sessionmaker
        factory = async_sessionmaker(db.bind, expire_on_commit=False)
        while not control["cancelled"]:
            await asyncio.sleep(1)
            async with factory() as probe:
                row = await operation_store.get_by_public_id(probe, public_id)
                if row is None or row.state not in ACTIVE_STATES or row.cancel_requested:
                    control["cancelled"] = True

    async def report(stage_name):
        row = await operation_store.get_by_public_id(db, public_id)
        if row is not None and row.state in ACTIVE_STATES:
            await operation_store.note(db, row, stage_name, MESSAGES.get(stage_name, stage_name))
            await db.commit()

    monitor = asyncio.create_task(watch())
    try:
        client = _bridge()
        try:
            session = await client.login_web_session(email=email, password=password, totp_secret=login_totp, proxy=proxy)
        except BridgeError as exc:
            return {"success": False, "status": "manual_required", "error_code": exc.code,
                    "error": MESSAGES.get(exc.code, exc.message), "phase": "none"}
        mfa = protocol_mfa_client(expected_email=email, storage_state_json=session["storage_state_json"], proxy=proxy)
        session.clear()
        result = await totp_reset.run_reset(db, email=email, client=mfa, operation_id=public_id,
            login_proof=uses_candidate, report=report, should_abort=lambda: control["cancelled"])
        return result
    except Exception:
        await db.rollback()
        return {"success": False, "status": "manual_required", "error_code": "reset_interrupted",
                "error": "换绑流程中断；请在「2FA 密钥」查询该邮箱的换绑状态，再重新发起核对", "phase": "unknown"}
    finally:
        control["cancelled"] = True
        monitor.cancel()
        await asyncio.gather(monitor, return_exceptions=True)


# ---------------------------------------------------------------- status

def _public(result: dict) -> dict:
    allowed = {"ok", "success", "status", "error_code", "message", "error", "phase", "backup_saved",
               "owner_synced", "extra_factors", "step", "remote_status", "remote_code",
               "login_success", "imported", "total", "results"}
    return {key: value for key, value in result.items() if key in allowed} if isinstance(result, dict) else {}


async def status_protocol(db, operation_id):
    row = await operation_store.get_by_public_id(db, str(operation_id))
    if row is None or row.op_type not in (LOGIN_OP, RESET_OP):
        return {"ok": False, "error_code": "not_found", "message": "任务不存在"}
    try:
        result = json.loads(row.result_json or "{}")
        inputs = json.loads(row.input_json or "{}")
    except (ValueError, TypeError):
        result, inputs = {}, {}
    stage = row.current_step or "running"
    return {"ok": True, "operation_id": row.public_id, "state": row.state, "status": row.state,
            "op_type": row.op_type, "stage": stage, "email": row.email,
            "mode": inputs.get("mode") if isinstance(inputs, dict) else None,
            "message": _public(result).get("message") or MESSAGES.get(stage) or "处理中",
            "result": _public(result), "cancel_requested": bool(row.cancel_requested)}


async def cancel_protocol(db, operation_id):
    row = await operation_store.get_by_public_id(db, str(operation_id))
    if row is None or row.op_type not in (LOGIN_OP, RESET_OP):
        return {"ok": False, "error_code": "not_found", "message": "任务不存在"}
    if row.state not in ACTIVE_STATES:
        return {"ok": True, "operation_id": row.public_id, "status": row.state, "message": "任务已结束"}
    row.cancel_requested = True
    await db.commit()
    return {"ok": True, "operation_id": row.public_id, "status": "cancelling", "message": "已请求停止；已发出的协议请求不会撤销"}


async def recover_protocol_auth(db):
    rows = list(await db.scalars(select(Operation).where(
        Operation.op_type.in_((LOGIN_OP, RESET_OP)), Operation.state.in_(("pending", *ACTIVE_STATES)))))
    for row in rows:
        await operation_store.finish(db, row, {"success": False, "status": "manual_required",
            "error_code": "interrupted", "error": "服务重启或任务中断，请重新发起；协议登录没有自动重放", "phase": "unknown"})
    await db.commit()
    return {"recovered": len(rows)}
