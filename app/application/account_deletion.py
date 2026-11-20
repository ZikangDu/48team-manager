"""Explicit local-only deletion of unassigned accounts; no provider calls."""

from sqlalchemy import delete, func, or_, select, update

from app.core.time import utcnow
from app.persistence.models.identity import Account, ExternalBinding, Workspace, WorkspaceMembership, WorkspaceOfficialMemberSnapshot
from app.persistence.models.oauth import OAuthSession
from app.persistence.models.codex import CodexBinding
from app.persistence.models.operations import Operation
from app.persistence.models.pool import StandbyPoolEntry
from app.persistence.models.quota import CredentialLease, QuotaProbeState, QuotaSnapshot
from app.persistence.models.resources import PhoneAttempt
from app.persistence.models.sub2api import Sub2ApiUsageSnapshot

BATCH_LIMIT = 50
POOL_DELETION_REASON = "账号仍在备用号池中。请在备用号池查看条目状态，并从那里移出符合条件的账号。"


class AccountDeletionError(ValueError):
    def __init__(self, code, message, status=409):
        super().__init__(message)
        self.code = code
        self.status = status


def can_delete_local_account(item: dict, *, kind: str | None = None) -> bool:
    if item.get("local_deletion") is not None:
        return bool(item["local_deletion"].get("allowed"))
    card_kind = kind or item.get("kind")
    return bool(
        item.get("id")
        and card_kind in {"unassigned", "history"}
        and item.get("purpose") != "mother"
        and item.get("management_role") != "mother"
        and not any(context.get("membership_state") != "removed" for context in item.get("contexts") or [])
    )


def local_deletion_policy(item: dict, *, owner_workspace_ids=(), member_workspace_ids=(), in_pool=False) -> dict:
    """Explain structural guards using the same local records as the DELETE endpoint.

    This is a read-model hint, not authorization: active tasks and leases are
    still checked transactionally immediately before deletion.
    """
    owned = sorted(set(owner_workspace_ids))
    linked = sorted(set(member_workspace_ids))
    if item.get("purpose") == "mother" or owned:
        reason = ("母号或团队所有者不能单独删除。请在所属团队的团队信息中管理本地团队记录。"
                  if owned or linked else "此账号的本地用途是母号，受本地删除保护。")
        return {"allowed": False, "code": "account_is_owner",
                "reason": reason,
                "workspace_ids": sorted(set(owned + linked))}
    if linked:
        return {"allowed": False, "code": "account_has_workspace",
                "reason": "账号仍有团队成员或邀请记录。请先在所属团队核对，确认离队或撤销邀请后同步，再删除本地档案。",
                "workspace_ids": linked}
    if in_pool:
        return {"allowed": False, "code": "account_in_pool", "reason": POOL_DELETION_REASON, "workspace_ids": []}
    return {"allowed": bool(item.get("id")), "code": None, "reason": "", "workspace_ids": []}


async def delete_unassigned_account(db, account_id: int):
    # Obtain the SQLite writer lock before checking guards, so queue claims cannot
    # interleave with the check-and-delete transaction. The caller commits/rolls back.
    await db.execute(update(Account).where(Account.id == account_id).values(version=Account.version))
    account = await db.get(Account, account_id, populate_existing=True)
    if account is None:
        raise AccountDeletionError("not_found", "账号不存在或已删除。", 404)
    email = account.email.strip().lower()
    owned = await db.scalar(select(Workspace.id).where(Workspace.owner_account_id == account_id).limit(1))
    if account.local_purpose == "mother" or owned is not None:
        raise AccountDeletionError("account_is_owner", "母号或团队所有者不能从此入口删除。")
    linked = await db.scalar(select(WorkspaceMembership.id).where(
        WorkspaceMembership.account_id == account_id,
        WorkspaceMembership.membership_state != "removed",
    ).limit(1))
    remote = await db.scalar(select(WorkspaceOfficialMemberSnapshot.id).where(
        func.lower(WorkspaceOfficialMemberSnapshot.normalized_email) == email,
        WorkspaceOfficialMemberSnapshot.remote_state.in_(("joined", "invited")),
    ).limit(1))
    if linked is not None or remote is not None:
        raise AccountDeletionError("account_has_workspace", "账号仍有团队成员或邀请记录，请先在对应团队处理并同步。")
    in_pool = await db.scalar(select(StandbyPoolEntry.id).where(StandbyPoolEntry.account_id == account_id))
    if in_pool is not None:
        raise AccountDeletionError("account_in_pool", POOL_DELETION_REASON)
    now = utcnow()
    busy = await db.scalar(select(Operation.id).where(
        or_(Operation.account_id == account_id, func.lower(Operation.email) == email,
            (Operation.entity_type == "account") & (Operation.entity_id == account_id)),
        Operation.state.in_(("pending", "queued", "running", "waiting")),
    ).limit(1))
    oauth = await db.scalar(select(OAuthSession.id).where(
        or_(OAuthSession.account_id == account_id, func.lower(OAuthSession.email) == email),
        OAuthSession.status.in_(("waiting", "exchanging")), OAuthSession.expires_at > now,
    ).limit(1))
    probe = await db.scalar(select(QuotaProbeState.context_key).where(
        QuotaProbeState.account_id == account_id, QuotaProbeState.lease_expires_at > now,
    ).limit(1))
    credential = await db.scalar(select(CredentialLease.account_id).where(
        CredentialLease.account_id == account_id, CredentialLease.expires_at > now,
    ).limit(1))
    codex = await db.scalar(select(CodexBinding.account_id).where(
        CodexBinding.account_id == account_id, CodexBinding.lease_until > now,
    ).limit(1))
    if any(value is not None for value in (busy, oauth, probe, credential, codex)):
        raise AccountDeletionError("account_busy", "账号有执行中、排队中或待完成的授权任务，请结束任务后再删除。")

    from app.persistence.models.sub2api_status import Sub2ApiAccountStatus
    await db.execute(delete(Sub2ApiAccountStatus).where(Sub2ApiAccountStatus.binding_id.in_(
        select(ExternalBinding.id).where(ExternalBinding.local_account_id == account_id))))
    for model, column in (
        (Sub2ApiUsageSnapshot, Sub2ApiUsageSnapshot.local_account_id),
        (ExternalBinding, ExternalBinding.local_account_id),
        (CodexBinding, CodexBinding.account_id),
        (QuotaSnapshot, QuotaSnapshot.account_id),
        (QuotaProbeState, QuotaProbeState.account_id),
        (CredentialLease, CredentialLease.account_id),
        (OAuthSession, OAuthSession.account_id),
        (WorkspaceMembership, WorkspaceMembership.account_id),
    ):
        await db.execute(delete(model).where(column == account_id))
    await db.execute(update(Account).where(Account.source_child_account_id == account_id).values(source_child_account_id=None))
    await db.execute(update(Operation).where(Operation.account_id == account_id).values(account_id=None))
    await db.execute(update(Operation).where(Operation.entity_type == "account", Operation.entity_id == account_id).values(entity_id=None))
    await db.execute(update(PhoneAttempt).where(PhoneAttempt.account_id == account_id).values(account_id=None))
    # Preserve HME/phone occupancy and operation audit history; these are not free resources.
    await db.execute(delete(Account).where(Account.id == account_id))
    return {
        "ok": True,
        "deleted_account_id": account_id,
        "email": account.email,
        "message": "本地账号档案已永久删除，远端账号及别名未改动。",
    }


async def delete_unassigned_accounts(db, account_ids: list[int]):
    ids = list(dict.fromkeys(int(account_id) for account_id in account_ids))
    if not ids:
        raise AccountDeletionError("empty_selection", "请先选择要删除的账号。", 400)
    if len(ids) > BATCH_LIMIT:
        raise AccountDeletionError("too_many", f"一次最多删除 {BATCH_LIMIT} 个账号。", 400)
    deleted = []
    failed = []
    for account_id in ids:
        try:
            result = await delete_unassigned_account(db, account_id)
            await db.commit()
            deleted.append({"account_id": result["deleted_account_id"], "email": result["email"]})
        except AccountDeletionError as exc:
            await db.rollback()
            failed.append({"account_id": account_id, "error_code": exc.code, "message": str(exc)})
    if deleted and not failed:
        message = f"已永久删除 {len(deleted)} 个本地档案，远端账号及别名未改动。"
    elif deleted:
        message = f"已删除 {len(deleted)} 个本地档案，{len(failed)} 个未删除。"
    else:
        message = failed[0]["message"] if len(failed) == 1 else f"{len(failed)} 个账号都未删除。"
    return {
        "ok": bool(deleted) and not failed,
        "partial": bool(deleted and failed),
        "deleted": deleted,
        "failed": failed,
        "message": message,
    }
