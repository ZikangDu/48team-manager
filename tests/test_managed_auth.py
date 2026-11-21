"""Offline mother/child matching, pinned exits and automatic credential saves."""
import unittest
from unittest.mock import AsyncMock, patch

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.main  # register all models
from app.application import credential_import, protocol_auth
from app.application.bridge_autosave import save_authorizations
from app.application.managed_auth import AuthRoute, AuthRouteError, match_account_memberships, resolve_auth_route
from app.application.operations import operation_store
from app.application.tokens import decrypt_secret, encrypt_secret
from app.core.time import utcnow
from app.persistence.database import Base
from app.persistence.models.identity import Account, Workspace, WorkspaceMembership, WorkspaceOfficialMemberSnapshot
from tests.test_credential_import import EMAIL, WS, OTHER_WS, record, token


class ManagedAuthTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.db = async_sessionmaker(self.engine, expire_on_commit=False)()
        self.addAsyncCleanup(self.engine.dispose)
        self.addAsyncCleanup(self.db.close)
        self.owner = Account(email="owner@example.com", local_purpose="mother", proxy="http://user:private@proxy.test:8080")
        self.db.add(self.owner)
        await self.db.flush()
        self.team = Workspace(name="Mother team", official_workspace_id=WS, owner_account_id=self.owner.id, status="active")
        self.db.add(self.team)
        await self.db.flush()
        self.db.add(WorkspaceOfficialMemberSnapshot(workspace_id=self.team.id, normalized_email=EMAIL,
            official_role="member", official_user_id="user-member", remote_state="joined", fetched_at=utcnow()))
        await self.db.commit()

    async def test_unregistered_member_inherits_mother_proxy_without_creating_account(self):
        route = await resolve_auth_route(self.db, EMAIL)
        self.assertEqual((route.proxy, route.source, route.workspace_id),
                         (self.owner.proxy, "workspace_owner", self.team.id))
        self.assertIsNone(await self.db.scalar(select(Account).where(Account.email == EMAIL)))

    async def test_own_proxy_wins_and_explicit_different_exit_is_blocked(self):
        child = Account(email=EMAIL, local_purpose="child", proxy="socks5://own.test:1080")
        self.db.add(child); await self.db.commit()
        route = await resolve_auth_route(self.db, EMAIL, mode="inherit", workspace_id=self.team.id)
        self.assertEqual(route.proxy, "socks5h://own.test:1080")
        with self.assertRaises(AuthRouteError) as caught:
            await resolve_auth_route(self.db, EMAIL, mode="custom", proxy="http://other.test:8000")
        self.assertEqual(caught.exception.code, "proxy_mismatch")

    async def test_missing_mother_proxy_fails_closed(self):
        self.owner.proxy = None; await self.db.commit()
        with self.assertRaises(AuthRouteError) as caught:
            await resolve_auth_route(self.db, EMAIL)
        self.assertEqual(caught.exception.code, "owner_proxy_missing")

    async def test_matching_is_local_idempotent_and_preserves_explicit_removal(self):
        child = Account(email=EMAIL, local_purpose="standby")
        self.db.add(child); await self.db.flush()
        self.assertEqual(await match_account_memberships(self.db, child), 1)
        self.assertEqual(child.local_purpose, "child")
        self.assertEqual(await match_account_memberships(self.db, child), 0)
        membership = await self.db.scalar(select(WorkspaceMembership).where(WorkspaceMembership.account_id == child.id))
        membership.membership_state = "removed"; await self.db.flush()
        self.assertEqual(await match_account_memberships(self.db, child), 0)
        self.assertEqual(membership.membership_state, "removed")

    async def test_membership_does_not_match_a_conflicting_official_user(self):
        child = Account(email=EMAIL, local_purpose="standby", official_user_id="other-user")
        self.db.add(child); await self.db.flush()
        self.assertEqual(await match_account_memberships(self.db, child), 0)

    async def test_multi_team_account_requires_selection_and_keeps_pinned_metadata(self):
        second = Workspace(name="Second team", official_workspace_id=OTHER_WS, owner_account_id=self.owner.id, status="active")
        self.db.add(second); await self.db.flush()
        self.db.add(WorkspaceOfficialMemberSnapshot(workspace_id=second.id, normalized_email=EMAIL,
            official_role="member", remote_state="joined", fetched_at=utcnow()))
        await self.db.commit()
        with self.assertRaises(AuthRouteError) as caught:
            await resolve_auth_route(self.db, EMAIL)
        self.assertEqual(caught.exception.code, "workspace_selection_required")
        route = await resolve_auth_route(self.db, EMAIL, workspace_id=second.id)
        self.assertEqual(route.workspace_id, second.id)
        child = Account(email=EMAIL, local_purpose="child", proxy=self.owner.proxy,
                        proxy_source="sub2api", sub2api_proxy_id=123, proxy_instance_key="instance")
        self.db.add(child); await self.db.commit()
        same = await resolve_auth_route(self.db, EMAIL, mode="custom", proxy=child.proxy, workspace_id=second.id)
        self.assertEqual((same.source, same.remote_id, same.instance_key), ("sub2api", 123, "instance"))

    async def test_remote_refresh_owner_is_not_overwritten_by_auto_save(self):
        child = Account(email=EMAIL, local_purpose="child", access_token_encrypted=encrypt_secret("existing"))
        self.db.add(child); await self.db.commit()
        with patch.object(credential_import, "refresh_owner_kind", AsyncMock(return_value="sub2api")):
            result = await save_authorizations(self.db, [record()])
        self.assertEqual(result["saved"], 0)
        self.assertEqual(result["results"][0]["code"], "remote_refresh_owned")
        self.assertEqual(decrypt_secret(child.access_token_encrypted), "existing")

    async def test_auto_save_matches_new_child_and_repeated_result_does_not_replace_tokens(self):
        credentials = record()
        saved = await save_authorizations(self.db, [credentials])
        self.assertEqual(saved["saved"], 1, saved)
        child = await self.db.scalar(select(Account).where(Account.email == EMAIL))
        self.assertEqual(child.local_purpose, "child")
        self.assertEqual((child.proxy, child.proxy_source), (self.owner.proxy, "workspace_owner"))
        revision = child.credential_revision
        again = await save_authorizations(self.db, [credentials])
        self.assertEqual(again["results"][0]["status"], "unchanged")
        self.assertEqual(child.credential_revision, revision)

    async def test_auto_save_selects_known_team_instead_of_personal_workspace(self):
        saved = await save_authorizations(self.db, [record(workspace=OTHER_WS), record()])
        self.assertEqual((saved["saved"], saved["blocked"]), (1, 0), saved)
        child = await self.db.scalar(select(Account).where(Account.email == EMAIL))
        self.assertEqual(child.official_account_id, WS)

    async def test_auto_save_requires_manual_selection_for_ambiguous_teams(self):
        other = "unknown@example.com"
        saved = await save_authorizations(self.db, [record(other), record(other, OTHER_WS)])
        self.assertEqual(saved["saved"], 0)
        self.assertEqual(saved["results"][0]["code"], "workspace_selection_required")

    async def test_auto_save_keeps_existing_refresh_token_when_result_is_partial(self):
        await save_authorizations(self.db, [record()])
        result = await save_authorizations(self.db, [{"email": EMAIL, "access_token": token(jti="new-no-rt")}])
        self.assertEqual(result["results"][0]["code"], "refresh_token_missing")
        child = await self.db.scalar(select(Account).where(Account.email == EMAIL))
        self.assertEqual(decrypt_secret(child.refresh_token_encrypted), "rt-fixture-private")

    async def test_batch_import_uses_team_token_and_persists_inherited_exit(self):
        route = await resolve_auth_route(self.db, EMAIL)
        row = {"openai_access_token": token(workspace=OTHER_WS), "openai_account_id": OTHER_WS,
               "business_workspace_credentials": [{"workspaceId": WS, "accountId": WS,
                   "accessToken": token(), "refreshToken": "team-refresh"}]}
        result = await protocol_auth._import_account(self.db, EMAIL, row, auth_route=route)
        self.assertEqual(result, "imported")
        child = await self.db.scalar(select(Account).where(Account.email == EMAIL))
        self.assertEqual((child.official_account_id, child.proxy, child.proxy_source), (WS, self.owner.proxy, "workspace_owner"))

    async def test_failed_route_does_not_send_credentials_and_other_accounts_continue(self):
        op = await operation_store.create(self.db, op_type=protocol_auth.LOGIN_OP)
        await self.db.commit()
        accounts = [{"email": EMAIL, "password": "never-send", "totp": "", "route_error": {
            "code": "owner_proxy_missing", "message": "母号代理未配置"}},
            {"email": "valid@example.com", "password": "fixture", "totp": ""}]
        login = AsyncMock(return_value=[{"email": "valid@example.com", "ok": False, "code": "bridge_credentials_rejected"}])
        with patch.object(protocol_auth, "_bridge") as bridge:
            bridge.return_value.login_batch = login
            result = await protocol_auth._run_batch(self.db, op.public_id, accounts, "http://proxy.test:8080", 2)
        self.assertEqual(result["total"], 2)
        self.assertNotIn("never-send", str(login.call_args))
        self.assertEqual(result["results"][0]["code"], "owner_proxy_missing")

    async def test_different_exits_are_never_mixed_in_one_bridge_batch(self):
        op = await operation_store.create(self.db, op_type=protocol_auth.LOGIN_OP)
        await self.db.commit()
        seen = []

        async def login(accounts, **options):
            seen.append((options["proxy"], [item["email"] for item in accounts]))
            return [{"email": item["email"], "ok": False, "code": "bridge_credentials_rejected"} for item in accounts]

        accounts = [{"email": email, "password": "fixture", "totp": "", "route": AuthRoute(proxy, "manual")}
                    for email, proxy in [(EMAIL, "http://one.test:8000"), ("two@example.com", "http://two.test:8000"),
                                         ("three@example.com", "http://one.test:8000")]]
        with patch.object(protocol_auth, "_bridge") as bridge:
            bridge.return_value.login_batch = AsyncMock(side_effect=login)
            result = await protocol_auth._run_batch(self.db, op.public_id, accounts, "", 3)
        self.assertEqual(result["total"], 3)
        self.assertEqual(seen, [("http://one.test:8000", [EMAIL, "three@example.com"]),
                                ("http://two.test:8000", ["two@example.com"])])


if __name__ == "__main__":
    unittest.main()
