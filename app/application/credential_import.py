"""Preview and atomically import explicitly selected local authorization records.

Drafts never contain plaintext at rest, never leave this process, and are bound
to the database engine that created them. Import does not authorize membership,
change refresh ownership, push credentials, or call an external provider.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import StaleDataError

from app.application.refresh_ownership import refresh_owner_kind
from app.application.tokens import encrypt_secret
from app.core.time import utcnow
from app.domain.identity.policy import normalize_official_plan
from app.integrations.auth_bridge.credentials import (
    CredentialImportError,
    normalize_email,
    parse_credentials,
)
from app.persistence.models.codex import CodexBinding
from app.persistence.models.identity import Account, ExternalBinding, Workspace, WorkspaceMembership
from app.persistence.models.oauth import OAuthSession
from app.persistence.models.operations import Operation
from app.persistence.models.quota import CredentialLease, QuotaProbeState
from app.persistence.models.refresh_handoff import Sub2ApiRefreshHandoff
from app.persistence.models.sub2api import Sub2ApiRefreshAuthority

DRAFT_TTL_SECONDS = 15 * 60
MAX_DRAFTS = 32
MAX_DRAFT_BYTES = 16 * 1024 * 1024
_draft_cipher = Fernet(Fernet.generate_key())
_draft_lock = threading.RLock()
_drafts: OrderedDict[str, dict] = OrderedDict()


def clear_previews() -> None:
    """Discard every temporary draft during application shutdown."""
    with _draft_lock:
        _drafts.clear()


def discard_preview(draft_id: str) -> bool:
    with _draft_lock:
        key = str(draft_id)
        item = _drafts.get(key)
        if item is not None and item["state"] == "processing":
            raise CredentialImportError("preview_busy", "这份预览正在提交，暂时不能丢弃", 409)
        _drafts.pop(key, None)
        return bool(item is not None and item["state"] == "ready" and item["deadline"] > time.monotonic())


def preview_exists(draft_id: str) -> bool:
    """Whether a ready draft still exists; no payload or identity is exposed."""
    with _draft_lock:
        _prune()
        value = _drafts.get(str(draft_id))
        return bool(value and value["state"] == "ready" and value["deadline"] > time.monotonic())


def _database(db) -> str:
    bind = db.get_bind()
    url = str(getattr(bind, "url", ""))
    return f"{id(bind)}:{hashlib.sha256(url.encode()).hexdigest()}"


def _prune() -> None:
    now = time.monotonic()
    for key, value in list(_drafts.items()):
        if value["deadline"] <= now and value["state"] != "processing":
            _drafts.pop(key, None)


def _store(db, payload: dict) -> tuple[str, str]:
    encrypted = _draft_cipher.encrypt(json.dumps(payload, separators=(",", ":")).encode())
    if len(encrypted) > MAX_DRAFT_BYTES:
        raise CredentialImportError("draft_too_large", "解析后的授权内容过大，请拆分导入")
    with _draft_lock:
        _prune()
        while len(_drafts) >= MAX_DRAFTS or sum(len(item.get("payload", b"")) for item in _drafts.values()) + len(encrypted) > MAX_DRAFT_BYTES:
            removable = next((key for key, item in _drafts.items() if item["state"] != "processing"), None)
            if removable is None:
                raise CredentialImportError("preview_capacity", "当前导入任务较多，请稍后重试", 429)
            _drafts.pop(removable)
        identifier = secrets.token_urlsafe(32)
        expires = datetime.fromtimestamp(time.time() + DRAFT_TTL_SECONDS, timezone.utc).isoformat()
        _drafts[identifier] = {"database": _database(db), "deadline": time.monotonic() + DRAFT_TTL_SECONDS,
                               "payload": encrypted, "state": "ready", "expires_at": expires}
        return identifier, expires


def _claim(db, draft_id: str) -> dict:
    if not isinstance(draft_id, str) or len(draft_id) > 100:
        raise CredentialImportError("preview_invalid", "导入预览标识无效")
    with _draft_lock:
        _prune()
        value = _drafts.get(draft_id)
        if value is None or value["deadline"] <= time.monotonic():
            raise CredentialImportError("preview_expired", "导入预览已过期或已关闭，请重新解析", 410)
        if value["database"] != _database(db):
            raise CredentialImportError("preview_context_mismatch", "导入预览不属于当前数据库", 409)
        if value["state"] == "consumed":
            raise CredentialImportError("preview_consumed", "这份预览已经提交，请勿重复导入", 409)
        if value["state"] != "ready":
            raise CredentialImportError("preview_busy", "这份预览正在提交，请稍后查看结果", 409)
        try:
            result = json.loads(_draft_cipher.decrypt(value["payload"]))
        except (InvalidToken, ValueError, TypeError):
            _drafts.pop(draft_id, None)
            raise CredentialImportError("preview_invalid", "无法读取导入预览，请重新解析", 410) from None
        value["state"] = "processing"
        return result


def _release(draft_id: str, *, consumed: bool) -> None:
    with _draft_lock:
        item = _drafts.get(draft_id)
        if item is not None:
            item["state"] = "consumed" if consumed else "ready"
            if consumed:
                item["payload"] = b""


def _row(row, fields) -> dict | None:
    if row is None:
        return None
    return {key: getattr(row, key) for key in fields}


async def _account(db, email: str) -> Account | None:
    return await db.scalar(select(Account).where(func.lower(Account.email) == email).execution_options(populate_existing=True))


async def account_snapshot(db, email) -> dict | None:
    """Freeze identity, credentials, local purpose and binding state, not secrets."""
    email = normalize_email(email)
    account = await _account(db, email)
    if account is None:
        return None
    state = {"account": _row(account, (
        "id", "email", "credential_revision", "official_account_id", "official_user_id", "client_id",
        "local_purpose", "operational_state", "proxy", "proxy_source", "sub2api_proxy_id", "proxy_instance_key",
        "access_token_encrypted", "refresh_token_encrypted", "id_token_encrypted", "session_token_encrypted",
    ))}
    queries = (
        ("bindings", ExternalBinding, ExternalBinding.local_account_id, (
            "id", "provider", "workspace_id", "remote_account_id", "binding_state",
            "verified_email", "verified_workspace_id", "verified_official_account_id")),
        ("memberships", WorkspaceMembership, WorkspaceMembership.account_id, (
            "id", "workspace_id", "official_user_id", "official_role", "membership_state", "local_purpose")),
        ("owned", Workspace, Workspace.owner_account_id, ("id", "official_workspace_id", "status")),
    )
    for key, model, column, fields in queries:
        rows = list(await db.scalars(select(model).where(column == account.id).execution_options(populate_existing=True)))
        state[key] = [_row(row, [field for field in fields if hasattr(model, field)]) for row in sorted(rows, key=lambda item: item.id)]
    authority = await db.get(Sub2ApiRefreshAuthority, account.id, populate_existing=True)
    handoff = await db.get(Sub2ApiRefreshHandoff, account.id, populate_existing=True)
    codex = await db.get(CodexBinding, account.id, populate_existing=True)
    state["authority"] = _row(authority, ("epoch", "binding_id", "local_revision", "local_fingerprint", "instance_id"))
    state["handoff"] = _row(handoff, ("state", "authority_epoch", "acknowledged"))
    state["codex"] = _row(codex, ("target_url", "remote_account_id", "import_attempted", "state", "official_workspace_id"))
    fingerprint = hashlib.sha256(json.dumps(state, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
    return {"id": account.id, "credential_revision": int(account.credential_revision or 1), "fingerprint": fingerprint}


def _same_snapshot(expected, current) -> bool:
    if expected is None or isinstance(expected, dict) and expected.get("id") is None:
        return current is None
    return isinstance(expected, dict) and expected == current


async def _check_identity(db, account: Account, candidate: dict) -> None:
    workspace = candidate["workspace_id"]
    if account.official_account_id and account.official_account_id.lower() != workspace:
        raise CredentialImportError("workspace_conflict", "本地账号已使用其他工作区授权，不能直接覆盖", 409)
    if account.official_user_id and account.official_user_id != candidate["user_id"]:
        raise CredentialImportError("user_conflict", "令牌用户与本地账号身份不一致", 409)
    owned = list(await db.scalars(select(Workspace).where(Workspace.owner_account_id == account.id)))
    if any(row.official_workspace_id and row.official_workspace_id.lower() != workspace for row in owned):
        raise CredentialImportError("workspace_conflict", "母号团队与待导入工作区不一致", 409)
    memberships = list(await db.scalars(select(Workspace).join(WorkspaceMembership, WorkspaceMembership.workspace_id == Workspace.id).where(
        WorkspaceMembership.account_id == account.id, WorkspaceMembership.membership_state.in_(("joined", "invited")))))
    known = {row.official_workspace_id.lower() for row in memberships if row.official_workspace_id}
    if known and workspace not in known:
        raise CredentialImportError("workspace_conflict", "待导入授权不属于本地关联的团队", 409)
    bindings = list(await db.scalars(select(ExternalBinding).where(ExternalBinding.local_account_id == account.id)))
    for binding in bindings:
        if binding.binding_state == "conflict":
            raise CredentialImportError("binding_conflict", "账号的远端绑定存在身份冲突，请先核对", 409)
        if binding.verified_email and binding.verified_email.strip().lower() != candidate["email"]:
            raise CredentialImportError("binding_conflict", "远端绑定邮箱存在冲突，请先核对", 409)
        if binding.verified_workspace_id and binding.verified_workspace_id.lower() != workspace:
            raise CredentialImportError("binding_conflict", "远端绑定工作区与待导入授权不一致", 409)
        if binding.verified_official_account_id and binding.verified_official_account_id.lower() != workspace:
            raise CredentialImportError("binding_conflict", "远端绑定账号身份与待导入授权不一致", 409)
        if binding.workspace_id:
            bound = await db.get(Workspace, binding.workspace_id)
            if bound and bound.official_workspace_id and bound.official_workspace_id.lower() != workspace:
                raise CredentialImportError("binding_conflict", "远端绑定团队与待导入授权不一致", 409)


async def _guard(db, candidate: dict, *, ignore_operation_id: int | None = None) -> Account | None:
    if candidate["expires_timestamp"] <= time.time():
        raise CredentialImportError("access_token_expired", "预览中的访问令牌已经过期，请重新授权", 409)
    account = await _account(db, candidate["email"])
    stamp = utcnow()
    matches = [func.lower(Operation.email) == candidate["email"]]
    oauth_matches = [func.lower(OAuthSession.email) == candidate["email"]]
    if account is not None:
        await _check_identity(db, account, candidate)
        if account.operational_state in {"archived", "disabled"} or account.local_purpose == "disabled":
            raise CredentialImportError("account_disabled", "账号已归档或停用，请先在原管理入口处理", 409)
        if await refresh_owner_kind(db, account.id) is not None:
            raise CredentialImportError("remote_refresh_owned", "该账号的刷新权由 Sub2API 或 codex-rs 托管，不能覆盖", 409)
        matches.extend([Operation.account_id == account.id, (Operation.entity_type == "account") & (Operation.entity_id == account.id)])
        oauth_matches.append(OAuthSession.account_id == account.id)
        lease = await db.get(CredentialLease, account.id, populate_existing=True)
        if lease and lease.token and (lease.expires_at is None or _future(lease.expires_at, stamp)):
            raise CredentialImportError("account_busy", "账号正在刷新凭据，请完成后重试", 409)
        probe = await db.scalar(select(QuotaProbeState.context_key).where(QuotaProbeState.account_id == account.id, QuotaProbeState.lease_expires_at > stamp).limit(1))
        codex = await db.get(CodexBinding, account.id, populate_existing=True)
        if probe is not None or codex and codex.lease_until and _future(codex.lease_until, stamp):
            raise CredentialImportError("account_busy", "账号有正在执行的凭据或检测任务", 409)
    clauses = [or_(*matches), Operation.state.in_(("pending", "queued", "running", "waiting"))]
    if ignore_operation_id is not None:
        clauses.append(Operation.id != ignore_operation_id)
    busy = await db.scalar(select(Operation.id).where(*clauses).limit(1))
    oauth = await db.scalar(select(OAuthSession.id).where(or_(*oauth_matches), OAuthSession.status.in_(("waiting", "exchanging")), OAuthSession.expires_at > stamp).limit(1))
    if busy is not None or oauth is not None:
        raise CredentialImportError("account_busy", "账号有未完成的任务或授权会话，请结束后重新解析", 409)
    return account


def _future(value, now) -> bool:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return value > now


async def preview_import(db, content: str | dict | list, *, expected_email=None, expected_account=None, ignore_operation_id=None) -> dict:
    if ignore_operation_id is not None and (type(ignore_operation_id) is not int or ignore_operation_id <= 0):
        raise CredentialImportError("operation_invalid", "导入任务上下文无效")
    if expected_account is not None and not isinstance(expected_account, dict):
        raise CredentialImportError("snapshot_invalid", "账号快照无效")
    expected_email = normalize_email(expected_email) if expected_email is not None else None
    candidates, errors = parse_credentials(content)
    frozen: dict[str, dict | None] = {}
    public = []
    internal = []
    for candidate in candidates:
        email = candidate["email"]
        identifier = secrets.token_hex(12)
        if email not in frozen:
            frozen[email] = await account_snapshot(db, email)
        snapshot = frozen[email]
        item = {"id": identifier, "email": email, "workspace_id": candidate["workspace_id"],
                "workspace_name": candidate["workspace_name"], "format": candidate["format"],
                "account_id": snapshot["id"] if snapshot else None,
                "action": "update" if snapshot else "create", "has_refresh_token": bool(candidate["refresh_token"]),
                "expires_at": candidate["expires_at"], "allowed": True, "warnings": list(candidate["warnings"])}
        try:
            if expected_email and email != expected_email:
                raise CredentialImportError("email_mismatch", "认证结果不属于本次选定账号", 409)
            if expected_account is not None and not _same_snapshot(expected_account, snapshot):
                raise CredentialImportError("account_changed", "账号在认证过程中发生变化，请重新开始", 409)
            account = await _guard(db, candidate, ignore_operation_id=ignore_operation_id)
            if account and account.refresh_token_encrypted and not candidate["refresh_token"]:
                item["warnings"].append("将移除旧刷新凭据，之后需手动授权")
            if account:
                item["warnings"].append("仅替换所选账号的本地凭据，不修改用途、代理、团队关系或远端绑定")
        except CredentialImportError as exc:
            item.update(allowed=False, error={"code": exc.code, "message": exc.message})
        public.append(item)
        internal.append({**candidate, "id": identifier, "allowed": item["allowed"]})
    if not candidates:
        return {"ok": True, "draft_id": None, "expires_at": None, "candidates": [], "errors": errors}
    draft_id, expires = _store(db, {"candidates": internal, "snapshots": frozen, "ignore_operation_id": ignore_operation_id})
    return {"ok": True, "draft_id": draft_id, "expires_at": expires, "candidates": public, "errors": errors}


async def commit_import(db, draft_id, selected_ids: list[str], *, verify_quota=False) -> dict:
    if type(verify_quota) is not bool:
        raise CredentialImportError("selection_invalid", "额度验证选项无效")
    if not isinstance(selected_ids, list) or not 1 <= len(selected_ids) <= 50 or any(not isinstance(item, str) or len(item) > 100 for item in selected_ids):
        raise CredentialImportError("selection_invalid", "请选择 1 至 50 条有效授权记录")
    if len(set(selected_ids)) != len(selected_ids):
        raise CredentialImportError("selection_duplicate", "同一候选记录不能重复选择")
    draft = _claim(db, draft_id)
    committed = False
    commit_started = False
    imported = []
    try:
        by_id = {item["id"]: item for item in draft["candidates"]}
        if any(identifier not in by_id for identifier in selected_ids):
            raise CredentialImportError("selection_invalid", "选择包含不属于此预览的记录")
        selected = [by_id[identifier] for identifier in selected_ids]
        if any(not item["allowed"] for item in selected):
            raise CredentialImportError("candidate_blocked", "所选记录包含不允许导入的授权，请重新解析", 409)
        if len({item["email"] for item in selected}) != len(selected):
            raise CredentialImportError("workspace_selection_required", "每个邮箱只能选择一组工作区凭据，请明确选择", 409)
        # Even an empty accounts table obtains SQLite's writer lock. No selected
        # row may change between CAS/ownership checks and the atomic import.
        await db.execute(update(Account).where(Account.id == -1).values(version=Account.version))
        checked = []
        for candidate in selected:
            current = await account_snapshot(db, candidate["email"])
            if not _same_snapshot(draft["snapshots"][candidate["email"]], current):
                raise CredentialImportError("account_changed", "预览后账号或绑定已变化，未覆盖任何凭据，请重新解析", 409)
            account = await _guard(db, candidate, ignore_operation_id=draft["ignore_operation_id"])
            checked.append((candidate, account))
        for candidate, account in checked:
            created = account is None
            if created:
                account = Account(email=candidate["email"], local_purpose="standby", operational_state="available", auth_state="unknown")
                db.add(account)
                await db.flush()
            # Replace the bundle as a whole. Never couple a new AT to an old RT,
            # ID token or session, even when the imported field is omitted.
            for field in ("access_token", "refresh_token", "id_token", "session_token"):
                setattr(account, field + "_encrypted", encrypt_secret(candidate[field]) if candidate[field] else None)
            account.credential_revision = int(account.credential_revision or 1) + 1
            account.official_account_id = candidate["workspace_id"]
            account.official_user_id = candidate["user_id"]
            account.client_id = candidate["client_id"]
            account.official_plan = normalize_official_plan(candidate["plan"])
            # Healthy is the credential-presence state used by existing manual
            # OAuth; the incremented revision makes quota_health show pending,
            # never a synthetic successful official check.
            account.auth_state = "healthy"
            await db.flush()
            imported.append({"id": account.id, "account_id": account.id, "email": account.email,
                             "workspace_id": candidate["workspace_id"], "action": "created" if created else "updated",
                             "credential_revision": account.credential_revision, "verification": "pending"})
        commit_started = True
        await db.commit()
        committed = True
    except CredentialImportError:
        await db.rollback()
        raise
    except (IntegrityError, StaleDataError):
        await db.rollback()
        raise CredentialImportError("account_changed", "账号被其他操作更新，未覆盖凭据，请重新解析", 409) from None
    except Exception:
        await db.rollback()
        raise CredentialImportError("import_failed", "授权导入未完成，请重新核对账号状态", 500) from None
    except BaseException:
        await db.rollback()
        raise
    finally:
        _release(draft_id, consumed=committed or commit_started)
    verification = []
    if verify_quota:
        from app.application.quota import quota_service
        for item in imported:
            try:
                account = await db.get(Account, item["account_id"], populate_existing=True)
                result = await quota_service.enqueue(db, account, source="credential_import")
                verification.append({"account_id": account.id, "queued": bool(result.get("ok")), "operation_id": result.get("operation_id")})
            except Exception:
                await db.rollback()
                verification.append({"account_id": item["account_id"], "queued": False, "message": "凭据已保存，额度验证未排队，请手动刷新额度"})
    return {"ok": True, "imported": imported, "count": len(imported), "verification": verification,
            "message": f"已导入 {len(imported)} 个账号的授权，等待官方验证；未修改团队成员或远端账号"}
