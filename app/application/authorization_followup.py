"""Durable, read-only official discovery after a locally saved authorization."""
from __future__ import annotations

import asyncio
import json
from datetime import timedelta

from sqlalchemy import or_, select, update

from app.application.identity import ensure_membership
from app.application.operations import WORKER_ID, operation_store, pack_input, unpack_input
from app.application.tokens import decrypt_secret
from app.core.time import utcnow
from app.domain.identity.ids import workspace_official_id
from app.domain.workspaces.metadata import title_from_mapping
from app.domain.workspaces.names import apply_official_name, placeholder_name
from app.integrations.openai.chatgpt import ChatGPTClient
from app.integrations.openai.member_adapter import normalize_official_role
from app.persistence.models.identity import Account, Workspace, WorkspaceMembership
from app.persistence.models.operations import Operation
from app.persistence.models.quota import QuotaSnapshot

TYPE = "authorization_followup"
ACTIVE = ("queued", "running", "waiting")


class ContextClient(ChatGPTClient):
    def __init__(self, proxy):
        super().__init__()
        self.fixed_proxy = proxy

    async def _proxy_for(self, db_session, identifier):
        return self.fixed_proxy or None


def context_identity(payload, target):
    """Role evidence must belong to the exact authorized, non-personal account."""
    target = workspace_official_id(target)
    if not target or not isinstance(payload, dict):
        return {"role": "unknown", "code": "workspace_identity_missing"}
    accounts = payload.get("accounts")
    nodes = []
    if isinstance(accounts, dict):
        for key, value in accounts.items():
            if workspace_official_id(key) == target and isinstance(value, dict):
                nodes.append(value)
    elif isinstance(accounts, list):
        for value in accounts:
            if not isinstance(value, dict):
                continue
            info = value.get("account") if isinstance(value.get("account"), dict) else value
            if workspace_official_id(info.get("account_id") or info.get("id")) == target:
                nodes.append(value)
    elif workspace_official_id(payload.get("account_id") or payload.get("id")) == target:
        nodes = [payload]
    if len(nodes) != 1:
        return {"role": "unknown", "code": "workspace_identity_missing"}
    wrapper = nodes[0]
    info = wrapper.get("account") if isinstance(wrapper.get("account"), dict) else wrapper
    found = workspace_official_id(info.get("account_id") or info.get("id"))
    if found and found != target:
        return {"role": "unknown", "code": "workspace_identity_conflict"}
    if info.get("is_deactivated") is True:
        return {"role": "unknown", "code": "workspace_deactivated"}
    structure = str(info.get("structure") or info.get("account_type") or "").lower()
    if structure == "personal" or info.get("is_personal_account") is True:
        return {"role": "personal", "code": "personal_workspace"}
    if structure not in {"workspace", "team", "business", "enterprise"} and info.get("is_personal_account") is not False:
        return {"role": "unknown", "code": "workspace_type_unknown"}
    roles = {normalize_official_role(node.get(key)) for node in (wrapper, info)
             for key in ("account_user_role", "role", "workspace_role", "user_role") if node.get(key)}
    if len(roles) != 1 or not roles <= {"owner", "member", "admin"}:
        return {"role": "unknown", "code": "workspace_role_unknown"}
    return {"role": roles.pop(), "workspace_id": target, "name": title_from_mapping(info), "code": "ok"}


async def enqueue(db, account_id, *, force=False):
    await db.execute(update(Account).where(Account.id == account_id).values(version=Account.version))
    account = await db.get(Account, account_id, populate_existing=True)
    if not account or not account.access_token_encrypted or account.operational_state in {"archived", "disabled"}:
        await db.commit()
        return {"queued": False, "code": "account_unavailable", "message": "账号没有可检查的有效授权。"}
    key = f"{TYPE}:{account.id}:{account.credential_revision}"
    previous = await db.scalar(select(Operation).where(Operation.op_type == TYPE, Operation.idempotency_key == key)
                               .order_by(Operation.id.desc()).limit(1))
    completed_ready = False
    if previous and previous.state == "success" and not force:
        outcome = json.loads(previous.result_json or "{}")
        ws_id = outcome.get("workspace_id")
        fresh = await db.scalar(select(QuotaSnapshot.id).where(QuotaSnapshot.account_id == account.id,
            QuotaSnapshot.workspace_id == ws_id, QuotaSnapshot.credential_revision == account.credential_revision,
            QuotaSnapshot.accepted.is_(True), QuotaSnapshot.success.is_(True),
            QuotaSnapshot.queried_at >= utcnow() - timedelta(minutes=15)).limit(1))
        checking = await db.scalar(select(Operation.id).where(Operation.op_type == "quota_probe",
            Operation.account_id == account.id, Operation.workspace_id == ws_id, Operation.state.in_(ACTIVE)).limit(1))
        sync = await operation_store.get_by_public_id(db, outcome["sync_operation_id"]) if outcome.get("sync_operation_id") else None
        completed_ready = bool(fresh or checking) and (sync is None or sync.state in {*ACTIVE, "success", "partial"})
    if previous and (previous.state in ACTIVE or completed_ready):
        result = {"queued": previous.state in ACTIVE, "operation_id": previous.public_id,
                  "account_id": account.id, "status": previous.state, "reused": True}
        await db.commit()
        return result
    operation = await operation_store.create(db, op_type=TYPE, account_id=account.id, email=account.email,
        source="credential_update", state="queued", input_payload={"credential_revision": account.credential_revision, "attempt": 0})
    operation.idempotency_key = key
    await db.commit()
    return {"queued": True, "operation_id": operation.public_id, "account_id": account.id, "status": "queued"}


async def _apply_identity(db, account, identity):
    role = identity["role"]
    if role not in {"owner", "admin", "member"}:
        return {"role": role, "code": identity["code"]}
    matches = list(await db.scalars(select(Workspace).where(Workspace.official_workspace_id == identity["workspace_id"])))
    if len(matches) > 1:
        return {"role": "unknown", "code": "workspace_duplicate"}
    workspace = matches[0] if matches else None
    if workspace and workspace.status in {"disabled", "archived"}:
        return {"role": "unknown", "code": "workspace_disabled"}
    if workspace and role == "owner" and workspace.owner_account_id not in {None, account.id}:
        return {"role": "unknown", "code": "workspace_owner_conflict"}
    membership = await db.scalar(select(WorkspaceMembership).where(
        WorkspaceMembership.workspace_id == workspace.id, WorkspaceMembership.account_id == account.id)) if workspace else None
    if membership and membership.membership_state == "removed":
        return {"role": "unknown", "code": "membership_removed"}
    if not workspace:
        workspace = Workspace(official_workspace_id=identity["workspace_id"], status="active", name_source="placeholder")
        db.add(workspace)
        await db.flush()
    # The official read just succeeded on this account's actual direct route.
    # Freeze it explicitly so children can inherit direct without mistaking an
    # unresolved proxy reference for permission to fall back to direct.
    if not any((account.proxy, account.proxy_profile_id, account.sub2api_proxy_id, account.proxy_instance_key)) and account.proxy_source != "workspace_owner":
        account.proxy_source = "direct"
    if role == "owner":
        workspace.owner_account_id = account.id
        account.local_purpose = "mother"
    elif not await db.scalar(select(Workspace.id).where(Workspace.owner_account_id == account.id).limit(1)):
        account.local_purpose = "child"
    apply_official_name(workspace, identity.get("name"), owner_email=account.email if role == "owner" else None,
                        synced_at=utcnow(), payload_source="authorization_context")
    if not workspace.name:
        workspace.name = placeholder_name(workspace)
    await ensure_membership(db, workspace_id=workspace.id, account_id=account.id, official_role=role,
                            membership_state="joined", local_purpose="mother" if role == "owner" else "child",
                            joined_at=utcnow())
    return {"role": role, "code": "ok", "workspace_id": workspace.id}


async def _queue_quota(db, account, workspace_id=None):
    from app.application.quota import quota_service
    workspace = await quota_service.resolve_probe_workspace(db, account, workspace_id)
    workspace_id = workspace.id if workspace else None
    recent = await db.scalar(select(QuotaSnapshot.id).where(
        QuotaSnapshot.account_id == account.id, QuotaSnapshot.workspace_id == workspace_id,
        QuotaSnapshot.credential_revision == account.credential_revision, QuotaSnapshot.accepted.is_(True),
        QuotaSnapshot.success.is_(True), QuotaSnapshot.queried_at >= utcnow() - timedelta(minutes=15)).limit(1))
    if recent:
        return {"queued": False, "ready": True}
    result = await quota_service.enqueue(db, account, workspace_id, source=TYPE)
    return {"queued": bool(result.get("ok")), "operation_id": result.get("operation_id")}


async def _dispatch(db, *, now=None, client=None):
    """One lease per account revision; restart-safe and at most three read attempts."""
    stamp = now or utcnow()
    operation = await db.scalar(select(Operation).where(Operation.op_type == TYPE,
        Operation.state.in_(("queued", "waiting")),
        or_(Operation.lease_expires_at.is_(None), Operation.lease_expires_at <= stamp))
        .order_by(Operation.id).limit(1))
    if operation is None:
        return {"claimed": False}
    op_id = operation.id
    claimed = await db.execute(update(Operation).execution_options(synchronize_session=False).where(Operation.id == op_id, Operation.state.in_(("queued", "waiting")),
        or_(Operation.lease_expires_at.is_(None), Operation.lease_expires_at <= stamp)).values(
        state="running", locked_by=WORKER_ID, lease_expires_at=stamp + timedelta(seconds=90), current_step="discover_identity"))
    await db.commit()
    if claimed.rowcount != 1:
        return {"claimed": False}
    operation = await db.get(Operation, op_id, populate_existing=True)
    inputs = unpack_input(operation.input_json)
    revision = inputs.get("credential_revision")
    account = await db.get(Account, operation.account_id, populate_existing=True)
    if operation.cancel_requested or not account or account.credential_revision != revision or account.local_purpose == "disabled" or account.operational_state in {"archived", "disabled"}:
        await operation_store.finish(db, operation, {"success": False, "status": "cancelled", "error_code": "superseded"})
        await db.commit()
        return {"claimed": True, "status": "cancelled"}
    account_id = account.id
    from app.application.managed_auth import AuthRouteError, account_proxy, pinned
    try:
        fixed_proxy = await account_proxy(db, account) if pinned(account) else ""
    except AuthRouteError:
        await operation_store.finish(db, operation, {"success": False, "status": "manual_required", "role": "unknown",
            "code": "proxy_unavailable", "error_code": "proxy_unavailable", "error": "账号固定代理无法解析，未改用直连，请先修正代理。"})
        await db.commit()
        return {"claimed": True, "status": "manual_required"}
    if fixed_proxy and not account.proxy:
        account.proxy = fixed_proxy
    proxy = account.proxy
    access, official_id, email = decrypt_secret(account.access_token_encrypted), account.official_account_id, account.email
    await db.commit()
    reader = client or ContextClient(fixed_proxy)
    try:
        response = await asyncio.wait_for(reader.get_account_context(access, db, account_id=official_id, identifier=email), timeout=15)
    except Exception:
        response = {"success": False, "status_code": 0}
    finally:
        access = ""
        if client is None:
            await reader.clear_session(email)
    # Recheck after the official read; a concurrent new authorization wins.
    await db.execute(update(Account).where(Account.id == account_id).values(version=Account.version))
    account = await db.get(Account, account_id, populate_existing=True)
    operation = await db.get(Operation, op_id, populate_existing=True)
    if operation.cancel_requested or account is None or account.credential_revision != revision or account.proxy != proxy or account.local_purpose == "disabled" or account.operational_state in {"archived", "disabled"}:
        await operation_store.finish(db, operation, {"success": False, "status": "cancelled", "error_code": "superseded"})
        await db.commit()
        return {"claimed": True, "status": "cancelled"}
    identity = context_identity(response.get("data"), official_id) if response.get("success") else {"role": "unknown", "code": "identity_unavailable"}
    result = await _apply_identity(db, account, identity)
    await db.commit()
    try:
        result["quota"] = await _queue_quota(db, account, result.get("workspace_id"))
    except Exception:
        await db.rollback()
        result["quota"] = {"queued": False, "code": "quota_queue_failed"}
    if result["role"] == "owner":
        from app.application.jobs.workspace_sync import enqueue_workspace_sync
        try:
            sync = await enqueue_workspace_sync(db, result["workspace_id"], source=TYPE)
            result["sync_operation_id"] = sync.get("operation_id")
        except Exception:
            await db.rollback()
            result["sync_warning"] = "团队已登记，成员同步未排队，请在任务记录中重试。"
    operation = await db.get(Operation, op_id, populate_existing=True)
    attempt = int(inputs.get("attempt", 0)) + 1
    retry_read = not response.get("success") and response.get("status_code", 0) not in {400, 401, 403, 404}
    retry_queue = not (result["quota"].get("queued") or result["quota"].get("ready")) or bool(result.get("sync_warning"))
    retry = (retry_read or retry_queue) and attempt < 3
    if retry:
        operation.state = "queued"
        operation.locked_by = None
        operation.lease_expires_at = stamp + timedelta(seconds=20 * attempt)
        operation.input_json = pack_input({"credential_revision": revision, "attempt": attempt})
        operation.result_json = json.dumps(result)
        await operation_store.note(db, operation, "identity_retry", "官方身份读取暂未完成，已安排自动重试。", touch_lease=False)
    else:
        known = result["role"] in {"owner", "admin", "member", "personal"}
        success = known and (result["quota"].get("queued") or result["quota"].get("ready")) and not result.get("sync_warning")
        parts = [{"owner": "已识别母号", "member": "已识别子号", "admin": "已识别管理员成员",
                  "personal": "已识别个人工作区"}.get(result["role"], "官方角色暂未确认，请在任务记录核对")]
        parts.append("额度已核验" if result["quota"].get("ready") else "额度刷新已排队" if result["quota"].get("queued")
                     else "额度检查未排队，请在任务记录重试")
        if result["role"] == "owner":
            parts.append("成员同步已排队" if result.get("sync_operation_id") else "成员同步未排队，请在任务记录重试")
        error_code = "quota_queue_failed" if not (result["quota"].get("queued") or result["quota"].get("ready")) else "member_sync_queue_failed" if result.get("sync_warning") else result["code"]
        result.update(success=bool(success), status="success" if success else "partial" if known else "manual_required",
                      error_code=None if success else error_code, message="；".join(parts) + "。")
        if not success:
            result["error"] = result["message"]
        await operation_store.finish(db, operation, result)
    await db.commit()
    return {"claimed": True, "result": result}


async def dispatch(db, *, now=None, client=None):
    try:
        return await _dispatch(db, now=now, client=client)
    except Exception:
        await db.rollback()
        operation = await db.scalar(select(Operation).where(Operation.op_type == TYPE,
            Operation.state == "running", Operation.locked_by == WORKER_ID).order_by(Operation.id.desc()).limit(1))
        if operation:
            inputs = unpack_input(operation.input_json)
            attempt = int(inputs.get("attempt", 0)) + 1
            if attempt < 3:
                operation.input_json = pack_input({"credential_revision": inputs.get("credential_revision"), "attempt": attempt})
                operation.state = "queued"
                operation.locked_by = None
                operation.lease_expires_at = (now or utcnow()) + timedelta(seconds=20 * attempt)
            else:
                await operation_store.finish(db, operation, {"success": False, "status": "failed",
                    "error_code": "followup_failed", "error": "授权已保存，后台检查未完成，请在任务记录核对。"})
            await db.commit()
        return {"claimed": bool(operation), "error_code": "followup_failed"}


async def status(db, account_id):
    account = await db.get(Account, account_id)
    if account is None:
        return None
    key = f"{TYPE}:{account.id}:{account.credential_revision}"
    operation = await db.scalar(select(Operation).where(Operation.op_type == TYPE, Operation.idempotency_key == key)
                               .order_by(Operation.id.desc()).limit(1))
    result = json.loads(operation.result_json or "{}") if operation else {}
    role = result.get("role", "unknown")
    ws_id = result.get("workspace_id")
    if ws_id is None:
        from app.application.quota import quota_service
        try:
            ws = await quota_service.resolve_probe_workspace(db, account)
            ws_id = ws.id if ws else None
        except ValueError:
            pass
    active_quota = await db.scalar(select(Operation).where(Operation.op_type == "quota_probe",
        Operation.account_id == account.id, Operation.workspace_id == ws_id, Operation.state.in_(ACTIVE))
        .order_by(Operation.id.desc()).limit(1))
    latest = await db.scalar(select(QuotaSnapshot).where(QuotaSnapshot.account_id == account.id,
        QuotaSnapshot.workspace_id == ws_id, QuotaSnapshot.credential_revision == account.credential_revision,
        QuotaSnapshot.accepted.is_(True)).order_by(QuotaSnapshot.id.desc()).limit(1))
    quota = active_quota.state if active_quota else "ready" if latest and latest.success else "failed" if latest else "pending"
    sync = await operation_store.get_by_public_id(db, result["sync_operation_id"]) if result.get("sync_operation_id") else None
    pending = operation is not None and operation.state in ACTIVE
    if quota == "pending" and not pending:
        quota = "failed"
    role_text = "正在自动识别官方角色" if pending else {
        "owner": "已识别母号", "member": "已识别子号", "admin": "已识别管理员成员", "personal": "个人工作区，无需登记团队",
    }.get(role, "官方角色暂未确认，请在任务记录核对")
    quota_text = {"ready": "额度刷新完成", "failed": "额度刷新未完成，请在任务记录核对",
                  "pending": "额度检查待排队", "queued": "额度刷新已排队", "running": "正在刷新额度", "waiting": "额度刷新等待中"}[quota]
    sync_text = ""
    if sync:
        sync_text = "成员同步中" if sync.state in ACTIVE else "成员同步完成" if sync.state in {"success", "partial"} else "成员同步未完成，请在任务记录核对"
    return {"ok": True, "account_id": account.id, "role": role,
        "operation_id": operation.public_id if operation else None, "state": operation.state if operation else "missing",
        "quota": quota, "sync": sync.state if sync else None,
        "done": not pending and quota not in {"pending", *ACTIVE} and (sync is None or sync.state not in ACTIVE),
        "message": "；".join(part for part in (role_text, quota_text, sync_text) if part)}
