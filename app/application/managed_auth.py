"""Local membership matching and frozen per-account login routes."""
from dataclasses import dataclass

from sqlalchemy import func, select

from app.core.crypto import token_cipher
from app.core.proxy import compose_proxy_url, normalize_proxy_url
from app.core.time import utcnow
from app.persistence.models.identity import Account, Workspace, WorkspaceMembership, WorkspaceOfficialMemberSnapshot
from app.persistence.models.resources import ProxyProfile


class AuthRouteError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


@dataclass(frozen=True)
class AuthRoute:
    proxy: str
    source: str
    workspace_id: int | None = None
    profile_id: int | None = None
    remote_id: int | None = None
    instance_key: str | None = None


def pinned(account):
    return account is not None and bool(account.proxy or account.proxy_profile_id or account.sub2api_proxy_id
                                        or account.proxy_instance_key or account.proxy_source in {"workspace_owner", "direct", "owner_direct"})


async def profile_url(db, profile_id):
    profile = await db.get(ProxyProfile, profile_id)
    if profile is None or profile.status != "active":
        raise AuthRouteError("proxy_unavailable", "所选代理档案不存在或已停用，请重新选择。")
    try:
        cipher = token_cipher()
        return normalize_proxy_url(compose_proxy_url(scheme=profile.scheme, host=profile.host, port=profile.port,
            username=cipher.decrypt(profile.username_encrypted) if profile.username_encrypted else "",
            password=cipher.decrypt(profile.password_encrypted) if profile.password_encrypted else "")) or ""
    except (ValueError, TypeError):
        raise AuthRouteError("proxy_unavailable", "代理档案无法读取，请在代理管理中修正。") from None


async def account_proxy(db, account):
    if account.proxy_source in {"direct", "owner_direct"} and not account.proxy:
        return ""
    try:
        if account.proxy:
            value = normalize_proxy_url(account.proxy)
        elif account.proxy_profile_id:
            value = await profile_url(db, account.proxy_profile_id)
        else:
            value = None
        if not value:
            raise ValueError
        return value
    except (ValueError, TypeError):
        raise AuthRouteError("proxy_unavailable", "账号的固定代理无法解析，请先修正代理绑定。") from None


async def member_workspaces(db, email, account=None):
    """Only current official evidence or active local memberships can select a team."""
    ids = set(await db.scalars(select(WorkspaceOfficialMemberSnapshot.workspace_id).where(
        WorkspaceOfficialMemberSnapshot.normalized_email == email,
        WorkspaceOfficialMemberSnapshot.remote_state.in_(("joined", "invited")))))
    if account:
        removed = set(await db.scalars(select(WorkspaceMembership.workspace_id).where(
            WorkspaceMembership.account_id == account.id, WorkspaceMembership.membership_state == "removed")))
        ids.difference_update(removed)
        ids.update(await db.scalars(select(WorkspaceMembership.workspace_id).where(
            WorkspaceMembership.account_id == account.id,
            WorkspaceMembership.membership_state.in_(("joined", "invited")))))
        ids.update(await db.scalars(select(Workspace.id).where(Workspace.owner_account_id == account.id)))
    return list(await db.scalars(select(Workspace).where(Workspace.id.in_(ids), Workspace.status == "active").order_by(Workspace.id)))


async def match_account_memberships(db, account, *, workspace_id=None):
    """Match existing accounts, never manufacture credentials from a member list."""
    if account.local_purpose in {"mother", "disabled"} or account.operational_state in {"archived", "disabled"}:
        return 0
    rows = (await db.execute(select(WorkspaceOfficialMemberSnapshot, Workspace).join(Workspace,
        Workspace.id == WorkspaceOfficialMemberSnapshot.workspace_id).where(
        WorkspaceOfficialMemberSnapshot.normalized_email == account.email.strip().lower(),
        WorkspaceOfficialMemberSnapshot.remote_state.in_(("joined", "invited")), Workspace.status == "active"))).all()
    matched = 0
    for snapshot, workspace in rows:
        if workspace_id is not None and workspace.id != workspace_id:
            continue
        if workspace.owner_account_id == account.id or snapshot.official_role == "owner":
            continue
        owner = await db.get(Account, workspace.owner_account_id) if workspace.owner_account_id else None
        if owner is None or owner.operational_state in {"archived", "disabled"} or owner.local_purpose == "disabled":
            continue
        if account.official_account_id and workspace.official_workspace_id != account.official_account_id:
            continue
        if account.official_user_id and snapshot.official_user_id and account.official_user_id != snapshot.official_user_id:
            continue
        existing = await db.scalar(select(WorkspaceMembership).where(
            WorkspaceMembership.workspace_id == workspace.id, WorkspaceMembership.account_id == account.id))
        # Explicitly removed memberships are not silently reactivated by matching.
        if existing is not None:
            continue
        db.add(WorkspaceMembership(workspace_id=workspace.id, account_id=account.id,
            official_role=snapshot.official_role or "member", official_user_id=snapshot.official_user_id,
            membership_state=snapshot.remote_state, local_purpose="child",
            joined_at=utcnow() if snapshot.remote_state == "joined" else None))
        if account.local_purpose == "standby":
            account.local_purpose = "child"
        matched += 1
    await db.flush()
    return matched


async def resolve_auth_route(db, email, *, mode="auto", workspace_id=None, proxy=None, profile_id=None):
    account = await db.scalar(select(Account).where(func.lower(Account.email) == email))
    if account and (account.operational_state in {"disabled", "archived"} or account.local_purpose == "disabled"):
        raise AuthRouteError("account_unavailable", "账号已停用，不能批量授权。")
    teams = await member_workspaces(db, email, account)
    if workspace_id is not None:
        team = await db.get(Workspace, workspace_id)
        if team is None or team.status != "active":
            raise AuthRouteError("workspace_unavailable", "所选团队不存在或已停用。")
        # A chosen team selects an exit, but does not invent membership evidence.
    elif len(teams) == 1:
        team = teams[0]
    elif account and account.official_account_id:
        team = next((item for item in teams if item.official_workspace_id == account.official_account_id), None)
    else:
        team = None
    if team is None and len(teams) > 1:
        raise AuthRouteError("workspace_selection_required", "账号属于多个团队，请明确选择母号团队。")
    own = await account_proxy(db, account) if pinned(account) else None
    if mode in {"auto", "inherit"} and own is not None:
        return AuthRoute(own, account.proxy_source or "manual", team.id if team else None,
                         account.proxy_profile_id, account.sub2api_proxy_id, account.proxy_instance_key)
    if mode in {"auto", "inherit"}:
        if team is not None:
            owner = await db.get(Account, team.owner_account_id) if team.owner_account_id else None
            if owner and (owner.operational_state in {"archived", "disabled"} or owner.local_purpose == "disabled"):
                raise AuthRouteError("owner_unavailable", "团队母号已停用，请先核对母号状态。")
            if not owner or not pinned(owner):
                raise AuthRouteError("owner_proxy_missing", "团队母号未绑定可用代理，请先配置母号代理。")
            value = await account_proxy(db, owner)
            return AuthRoute(value, "workspace_owner" if value else "owner_direct", team.id, owner.proxy_profile_id,
                             owner.sub2api_proxy_id, owner.proxy_instance_key)
        if mode == "inherit":
            raise AuthRouteError("workspace_selection_required", "尚未匹配团队，请先同步成员或选择母号团队。")
        mode = "default"
    try:
        if mode == "profile":
            value = await profile_url(db, profile_id)
        elif mode == "custom":
            value = normalize_proxy_url(proxy)
            if not value:
                raise ValueError
        elif mode == "direct":
            value = ""
        elif mode == "default":
            from app.core.config import load_settings
            value = normalize_proxy_url(load_settings().auth_bridge_proxy) or ""
        else:
            raise ValueError
    except (ValueError, TypeError):
        raise AuthRouteError("proxy_invalid", "代理配置无效，请使用完整的 HTTP 或 SOCKS5 代理地址。") from None
    if own is not None and own != value:
        raise AuthRouteError("proxy_mismatch", "所选代理与账号固定出口不同，请在账号详情核对代理。")
    if own is not None:
        return AuthRoute(own, account.proxy_source or "manual", team.id if team else None,
                         account.proxy_profile_id, account.sub2api_proxy_id, account.proxy_instance_key)
    return AuthRoute(value, "manual" if value else "direct", team.id if team else None, profile_id if mode == "profile" else None)


async def apply_auth_route(db, account, route):
    if pinned(account) and await account_proxy(db, account) != route.proxy:
        raise AuthRouteError("proxy_mismatch", "授权期间账号代理已变化，未覆盖凭据。")
    account.proxy = route.proxy or None
    account.proxy_source = route.source
    account.proxy_profile_id = route.profile_id
    account.sub2api_proxy_id = route.remote_id
    account.proxy_instance_key = route.instance_key
