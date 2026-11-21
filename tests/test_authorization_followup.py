"""No-network contracts for automatic classification, quota and member sync."""
import json
import unittest
from datetime import timedelta
from unittest.mock import AsyncMock, patch

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.main
from app.application import authorization_followup as service
from app.application.bridge_autosave import save_authorizations
from app.application.managed_auth import resolve_auth_route
from app.application.operations import recover_stale_operations
from app.application.tokens import encrypt_secret
from app.core.time import utcnow
from app.persistence.database import Base
from app.persistence.models.identity import Account, Workspace, WorkspaceMembership
from app.persistence.models.operations import Operation
from tests.test_credential_import import EMAIL, WS, OTHER_WS, record, token


def context(role="account-owner", structure="workspace", workspace=WS):
    return {"accounts": {workspace: {"account": {"account_id": workspace, "account_user_role": role,
            "structure": structure, "name": "Official Team"}}}}


class IdentityParsingTests(unittest.TestCase):
    def test_owner_member_admin_and_personal_are_distinct(self):
        for role, expected in [("account-owner", "owner"), ("standard-user", "member"), ("admin", "admin")]:
            self.assertEqual(service.context_identity(context(role), WS)["role"], expected)
        self.assertEqual(service.context_identity(context(structure="personal"), WS)["role"], "personal")

    def test_never_infers_ownership_from_a_plan_or_another_workspace(self):
        data = context(workspace=OTHER_WS)
        self.assertEqual(service.context_identity(data, WS)["role"], "unknown")
        data = context(); data["accounts"][WS]["account"].pop("account_user_role")
        data["accounts"][WS]["account"]["plan_type"] = "team"
        self.assertEqual(service.context_identity(data, WS)["role"], "unknown")
        data = context(); data["accounts"][WS]["account"]["account_id"] = OTHER_WS
        self.assertEqual(service.context_identity(data, WS)["code"], "workspace_identity_conflict")
        data = context(); data["accounts"][WS]["role"] = "member"
        self.assertEqual(service.context_identity(data, WS)["role"], "unknown")


class FollowupTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.db = async_sessionmaker(self.engine, expire_on_commit=False)()
        self.addAsyncCleanup(self.engine.dispose)
        self.addAsyncCleanup(self.db.close)
        self.account = Account(email=EMAIL, local_purpose="standby", official_account_id=WS,
            access_token_encrypted=encrypt_secret(token()), refresh_token_encrypted=encrypt_secret("private-fixture-rt"))
        self.db.add(self.account); await self.db.commit()

    def client(self, payload=None):
        client = AsyncMock()
        client.get_account_context.return_value = {"success": True, "data": payload or context()}
        return client

    async def test_saved_authorization_enqueues_once_without_network_or_token_replacement(self):
        value = record()
        saved = await save_authorizations(self.db, [value])
        self.assertEqual(saved["saved"], 1)
        followup = saved["results"][0]["followup"]
        self.assertTrue(followup["queued"])
        revision = self.account.credential_revision
        repeated = await save_authorizations(self.db, [value])
        self.assertEqual(repeated["results"][0]["followup"]["operation_id"], followup["operation_id"])
        self.assertEqual(self.account.credential_revision, revision)
        self.assertEqual(await self.db.scalar(select(func.count(Operation.id)).where(Operation.op_type == service.TYPE)), 1)

    async def test_owner_becomes_local_mother_and_queues_correct_quota_and_members(self):
        revision = self.account.credential_revision
        await service.enqueue(self.db, self.account.id)
        result = await service.dispatch(self.db, client=self.client())
        self.assertEqual(result["result"]["role"], "owner", result)
        workspace = await self.db.scalar(select(Workspace))
        self.assertEqual(workspace.owner_account_id, self.account.id)
        self.assertEqual((self.account.local_purpose, self.account.proxy_source), ("mother", "direct"))
        self.assertEqual(self.account.credential_revision, revision)
        membership = await self.db.scalar(select(WorkspaceMembership))
        self.assertEqual((membership.official_role, membership.membership_state), ("owner", "joined"))
        quota = await self.db.scalar(select(Operation).where(Operation.op_type == "quota_probe"))
        self.assertEqual(quota.workspace_id, workspace.id)
        sync = await self.db.scalar(select(Operation).where(Operation.op_type == "workspace_sync"))
        self.assertEqual(sync.workspace_id, workspace.id)
        route = await resolve_auth_route(self.db, "new-child@example.com", workspace_id=workspace.id, mode="inherit")
        self.assertEqual((route.proxy, route.source), ("", "owner_direct"))
        status = await service.status(self.db, self.account.id)
        self.assertEqual((status["role"], status["quota"], status["sync"]), ("owner", "queued", "queued"))
        self.assertNotIn("private-fixture-rt", json.dumps(result))

    async def test_member_is_a_child_and_does_not_gain_owner_or_member_sync_privileges(self):
        owner = Account(email="other-owner@example.com", local_purpose="mother")
        self.db.add(owner); await self.db.flush()
        workspace = Workspace(official_workspace_id=WS, owner_account_id=owner.id, status="active")
        self.db.add(workspace); await self.db.commit()
        await service.enqueue(self.db, self.account.id)
        result = await service.dispatch(self.db, client=self.client(context("standard-user")))
        self.assertEqual(result["result"]["role"], "member")
        self.assertEqual(self.account.local_purpose, "child")
        self.assertNotIn("成员同步已排队", result["result"]["message"])
        self.assertEqual(workspace.owner_account_id, owner.id)
        self.assertEqual(await self.db.scalar(select(func.count(Operation.id)).where(Operation.op_type == "workspace_sync")), 0)

    async def test_personal_owner_does_not_create_a_team(self):
        await service.enqueue(self.db, self.account.id)
        result = await service.dispatch(self.db, client=self.client(context(structure="personal")))
        self.assertEqual(result["result"]["role"], "personal")
        self.assertEqual(self.account.local_purpose, "standby")
        self.assertEqual(await self.db.scalar(select(func.count(Workspace.id))), 0)
        self.assertTrue(result["result"]["quota"]["queued"])

    async def test_existing_owner_conflict_is_not_overwritten(self):
        owner = Account(email="different-owner@example.com", local_purpose="mother")
        self.db.add(owner); await self.db.flush()
        workspace = Workspace(official_workspace_id=WS, owner_account_id=owner.id, status="active")
        self.db.add(workspace); await self.db.commit()
        await service.enqueue(self.db, self.account.id)
        result = await service.dispatch(self.db, client=self.client())
        self.assertEqual(result["result"]["code"], "workspace_owner_conflict")
        self.assertEqual(workspace.owner_account_id, owner.id)
        self.assertEqual(self.account.local_purpose, "standby")

    async def test_new_credentials_during_read_cancel_stale_classification(self):
        client = self.client()
        async def changed(*args, **kwargs):
            self.account.credential_revision += 1
            await self.db.commit()
            return {"success": True, "data": context()}
        client.get_account_context.side_effect = changed
        await service.enqueue(self.db, self.account.id)
        result = await service.dispatch(self.db, client=client)
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(await self.db.scalar(select(func.count(Workspace.id))), 0)

    async def test_transient_discovery_retries_but_quota_is_still_queued(self):
        client = self.client();client.get_account_context.return_value = {"success": False, "status_code": 503}
        await service.enqueue(self.db, self.account.id)
        stamp = utcnow()
        for delay in (0, 21, 80):
            await service.dispatch(self.db, client=client, now=stamp + timedelta(seconds=delay))
        operation = await self.db.scalar(select(Operation).where(Operation.op_type == service.TYPE))
        self.assertEqual(operation.state, "manual_required")
        self.assertEqual(client.get_account_context.await_count, 3)
        self.assertEqual(await self.db.scalar(select(func.count(Operation.id)).where(Operation.op_type == "quota_probe")), 1)

    async def test_restart_requeues_the_durable_read_only_followup(self):
        await service.enqueue(self.db, self.account.id)
        operation = await self.db.scalar(select(Operation).where(Operation.op_type == service.TYPE))
        operation.state = "running";operation.locked_by = None;operation.lease_expires_at = None
        await self.db.commit()
        await recover_stale_operations(self.db)
        self.assertEqual(operation.state, "queued")

    async def test_unresolved_pinned_proxy_does_not_fall_back_to_direct(self):
        self.account.proxy_source = "workspace_owner"
        await self.db.commit()
        await service.enqueue(self.db, self.account.id)
        client = self.client()
        result = await service.dispatch(self.db, client=client)
        self.assertEqual(result["status"], "manual_required")
        client.get_account_context.assert_not_awaited()
        self.assertEqual(await self.db.scalar(select(func.count(Operation.id)).where(Operation.op_type == "quota_probe")), 0)

    async def test_queue_failure_is_reported_truthfully_after_bounded_retry(self):
        await service.enqueue(self.db, self.account.id)
        client = self.client()
        stamp = utcnow()
        with patch.object(service, "_queue_quota", new=AsyncMock(side_effect=RuntimeError("fixture-only"))):
            for delay in (0, 21, 80):
                outcome = await service.dispatch(self.db, client=client, now=stamp + timedelta(seconds=delay))
        result = outcome["result"]
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["error_code"], "quota_queue_failed")
        self.assertIn("额度检查未排队", result["message"])
        self.assertNotIn("额度刷新已排队", result["message"])
        self.assertNotIn("fixture-only", str(result))
        from app.application.console_actions import get_operation_detail, retry_operation
        operation = await self.db.scalar(select(Operation).where(Operation.op_type == service.TYPE))
        detail = await get_operation_detail(self.db, operation.public_id)
        self.assertTrue(detail["can_retry"])
        retried = await retry_operation(self.db, operation.public_id)
        self.assertTrue(retried["ok"])
        self.assertNotEqual(retried["operation_id"], operation.public_id)

    async def test_unchanged_authorization_rechecks_a_failed_quota_instead_of_staying_pending(self):
        first = await service.enqueue(self.db, self.account.id)
        await service.dispatch(self.db, client=self.client())
        waiting = await service.enqueue(self.db, self.account.id)
        self.assertEqual(waiting["operation_id"], first["operation_id"])
        quota = await self.db.scalar(select(Operation).where(Operation.op_type == "quota_probe"))
        quota.state = "failed"
        await self.db.commit()
        retry = await service.enqueue(self.db, self.account.id)
        self.assertNotEqual(retry["operation_id"], first["operation_id"])
        self.assertTrue(retry["queued"])


if __name__ == "__main__":
    unittest.main()
