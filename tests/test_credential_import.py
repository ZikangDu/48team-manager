"""Credential import contracts against isolated databases and synthetic JWTs."""
from __future__ import annotations

import asyncio
import json
import tempfile
import time
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

import jwt
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.application import credential_import as service
from app.application.credential_import import CredentialImportError, account_snapshot, commit_import, preview_import
from app.application.tokens import decrypt_secret, encrypt_secret
from app.core.time import utcnow
from app.domain.automation import DEFAULT_OAUTH_CLIENT_ID
from app.integrations.auth_bridge.credentials import MAX_CONTENT_BYTES, parse_credentials
from app.persistence.database import Base
from app.persistence.models.codex import CodexBinding
from app.persistence.models.identity import Account, ExternalBinding, Workspace, WorkspaceMembership, WorkspaceOfficialMemberSnapshot
from app.persistence.models.oauth import OAuthSession
from app.persistence.models.operations import Operation
from app.persistence.models.quota import CredentialLease, QuotaSnapshot
from app.persistence.models.sub2api import Sub2ApiRefreshAuthority

WS = "00000000-0000-4000-8000-000000000001"
OTHER_WS = "00000000-0000-4000-8000-000000000002"
EMAIL = "member@example.com"


def token(email=EMAIL, workspace=WS, user="user-member", client=DEFAULT_OAUTH_CLIENT_ID, exp=None, **claims):
    return jwt.encode({"email": email, "client_id": client, "exp": exp or int(time.time()) + 3600,
                       "https://api.openai.com/auth": {"chatgpt_account_id": workspace, "chatgpt_user_id": user,
                                                       "chatgpt_plan_type": "team"}, **claims},
                      "synthetic-fixture-not-a-real-key", algorithm="HS256")


def record(email=EMAIL, workspace=WS, **values):
    return {"email": email, "access_token": token(email, workspace), "refresh_token": "rt-fixture-private", **values}


def selected(preview):
    return [row["id"] for row in preview["candidates"]]


class ParsingTests(unittest.TestCase):
    def test_standard_cpa_sub2api_session_and_nested_envelopes(self):
        access = token()
        formats = [
            {"access_token": access, "email": EMAIL},
            {"type": "codex", "access_token": access, "refresh_token": "rt", "account_id": WS},
            {"type": "sub2api-data", "accounts": [{"platform": "openai", "type": "oauth", "credentials": {"access_token": access, "refresh_token": "rt", "chatgpt_account_id": WS, "email": EMAIL}}]},
            {"accessToken": access, "user": {"email": EMAIL, "id": "user-member"}, "account": {"id": WS}},
            {"tokens": {"access_token": access, "refresh_token": "rt"}, "email": EMAIL},
        ]
        parsed, errors = parse_credentials(formats)
        self.assertEqual(len(parsed), 5)
        self.assertEqual(errors, [])
        self.assertTrue(all(row["workspace_id"] == WS and row["email"] == EMAIL for row in parsed))

    def test_bridge_workspace_arrays_and_personal_credentials(self):
        content = {"browserState": {"accounts": [{"id": "bridge-private-id", "email": EMAIL,
            "password": "ignored-password", "totp_secret": "IGNOREDTOTP",
            "openai_access_token": token(), "openai_rt": "personal-rt", "openai_account_id": WS,
            "business_workspace_credentials": [{"workspaceId": OTHER_WS, "accountId": OTHER_WS,
                "accessToken": token(workspace=OTHER_WS), "refreshToken": "workspace-rt", "workspaceName": "Team"}]}]}}
        parsed, errors = parse_credentials(content)
        self.assertEqual(errors, [])
        self.assertEqual({row["workspace_id"] for row in parsed}, {WS, OTHER_WS})
        self.assertNotIn("ignored-password", json.dumps(parsed))
        self.assertNotIn("IGNOREDTOTP", json.dumps(parsed))
        wrapped, _ = parse_credentials({"state": {"browserAccounts": content["browserState"]["accounts"]}})
        self.assertEqual(len(wrapped), 2)

    def test_bridge_session_and_legacy_workspace_fields(self):
        parsed, errors = parse_credentials({"accounts": [{"email": EMAIL,
            "session_json": json.dumps({"accessToken": token(), "user": {"email": EMAIL}}),
            "business_workspace_id": OTHER_WS, "business_openai_account_id": OTHER_WS,
            "business_openai_access_token": token(workspace=OTHER_WS), "business_openai_rt": "rt"}]})
        self.assertEqual(errors, [])
        self.assertEqual(len(parsed), 2)

    def test_authoritative_left_workspace_is_not_imported(self):
        content = {"email": EMAIL, "business_workspace_id": WS, "business_openai_access_token": token(),
                   "business_workspace_credentials": [{"workspaceId": WS, "status": "left"}]}
        parsed, errors = parse_credentials(content)
        self.assertEqual(parsed, [])
        self.assertEqual(errors[0]["code"], "access_token_missing")

    def test_bridge_session_conflicting_access_tokens_are_rejected_before_alias_override(self):
        outer = token(jti="outer-session-fixture")
        inner = token(jti="inner-session-fixture")
        for alias in ("accessToken", "access_token"):
            for as_text in (False, True):
                session = {alias: inner, "refresh_token": "inner-rt-private", "email": EMAIL}
                with self.subTest(alias=alias, as_text=as_text), self.assertRaises(CredentialImportError) as caught:
                    parse_credentials({"email": EMAIL, "session_access_token": outer,
                                       "session_json": json.dumps(session) if as_text else session})
                self.assertEqual(caught.exception.code, "token_conflict")
                self.assertNotIn(outer, str(caught.exception))
                self.assertNotIn(inner, str(caught.exception))
                self.assertNotIn("inner-rt-private", str(caught.exception))
        with self.assertRaises(CredentialImportError) as caught:
            parse_credentials({"email": EMAIL, "session_json": {"accessToken": outer, "access_token": inner}})
        self.assertEqual(caught.exception.code, "token_conflict")

    def test_bridge_session_inner_email_cannot_be_replaced_by_outer_email(self):
        access = token()
        for inner in ({"email": "other@example.com"}, {"chatgpt_email": "other@example.com"},
                      {"user": {"email": "other@example.com"}}):
            with self.subTest(inner=inner), self.assertRaises(CredentialImportError) as caught:
                parse_credentials({"email": EMAIL, "session_access_token": access,
                                   "session_json": {"accessToken": access, **inner}})
            self.assertEqual(caught.exception.code, "email_mismatch")

    def test_matching_bridge_session_aliases_keep_one_complete_bundle(self):
        access = token()
        parsed, errors = parse_credentials({"email": EMAIL.upper(), "session_access_token": access,
            "session_json": {"accessToken": access, "access_token": access, "email": EMAIL,
                             "user": {"email": EMAIL}, "refresh_token": "matching-rt"}})
        self.assertEqual(errors, [])
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["access_token"], access)
        self.assertEqual(parsed[0]["refresh_token"], "matching-rt")

    def test_legacy_bridge_workspace_conflicts_cannot_be_replaced_by_array(self):
        access = token(jti="current-fixture")
        content = {"email": EMAIL, "business_workspace_id": WS, "business_openai_account_id": WS,
                   "business_openai_access_token": access, "business_openai_rt": "legacy-rt-private",
                   "business_openai_id_token": access}
        variants = [
            ({"accessToken": token(jti="other-fixture")}, "token_conflict"),
            ({"refreshToken": "different-rt-private"}, "token_conflict"),
            ({"idToken": token(jti="other-id-fixture")}, "token_conflict"),
            ({"accountId": OTHER_WS}, "workspace_mismatch"),
            ({"credentials": {"refresh_token": "nested-rt-private"}}, "token_conflict"),
        ]
        for changes, code in variants:
            # Equivalent UUID spellings must still identify the same workspace.
            item = {"workspaceId": WS.replace("-", ""), "accessToken": access, **changes}
            with self.subTest(changes=list(changes)), self.assertRaises(CredentialImportError) as caught:
                parse_credentials({**content, "business_workspace_credentials": [item]})
            self.assertEqual(caught.exception.code, code)
            self.assertNotIn("private", str(caught.exception))

    def test_matching_legacy_workspace_copy_does_not_fill_missing_array_refresh_token(self):
        access = token()
        content = {"email": EMAIL, "business_workspace_id": WS, "business_openai_access_token": access,
                   "business_openai_rt": "legacy-rt",
                   "business_workspace_credentials": [{"workspaceId": WS, "accessToken": access}]}
        parsed, errors = parse_credentials(content)
        self.assertEqual(errors, [])
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["refresh_token"], "")
        content["business_workspace_credentials"][0]["refreshToken"] = "legacy-rt"
        parsed, errors = parse_credentials(content)
        self.assertEqual(errors, [])
        self.assertEqual(parsed[0]["refresh_token"], "legacy-rt")

    def test_explicit_left_workspace_excludes_conflicting_legacy_copy(self):
        parsed, errors = parse_credentials({"email": EMAIL, "business_workspace_id": WS,
            "business_openai_access_token": token(jti="legacy-fixture"),
            "business_workspace_credentials": [{"workspaceId": WS.replace("-", ""),
                "accessToken": token(jti="discarded-fixture"), "status": "left"}]})
        self.assertEqual(parsed, [])
        self.assertEqual(errors[0]["code"], "access_token_missing")

    def test_bridge_workspace_inner_email_cannot_be_replaced_by_outer_email(self):
        with self.assertRaises(CredentialImportError) as caught:
            parse_credentials({"email": EMAIL, "business_workspace_credentials": [{
                "workspaceId": WS, "accessToken": token(), "email": "other@example.com"}]})
        self.assertEqual(caught.exception.code, "email_mismatch")

    def test_synthetic_id_token_is_ignored_not_used_as_identity(self):
        parsed, errors = parse_credentials(record(id_token="not-a-jwt-and-must-be-ignored", id_token_synthetic=True))
        self.assertEqual(errors, [])
        self.assertEqual(parsed[0]["id_token"], "")
        self.assertTrue(any("合成" in message for message in parsed[0]["warnings"]))

    def test_identity_mismatches_expired_missing_and_agent_credentials(self):
        cases = [
            (record(email="wrong@example.com", access_token=token()), "email_mismatch"),
            (record(workspace_id=OTHER_WS), "workspace_mismatch"),
            (record(chatgpt_user_id="user-other"), "user_mismatch"),
            (record(client_id="client-other"), "client_mismatch"),
            (record(access_token=token(exp=int(time.time()) - 5)), "access_token_expired"),
            (record(access_token=token(user="")), "identity_missing"),
            (record(access_token=token(client="")), "identity_missing"),
            (record(id_token=token(email="wrong@example.com")), "id_token_mismatch"),
            (record(account_id=42), "workspace_missing"),
            ({"credentials": {"auth_mode": "agent_identity", "agent_private_key": "DO-NOT-LEAK"}}, "auth_mode_unsupported"),
        ]
        for value, code in cases:
            with self.subTest(code=code):
                parsed, errors = parse_credentials(value)
                self.assertEqual(parsed, [])
                self.assertEqual(errors[0]["code"], code)
                self.assertNotIn(value.get("access_token", "DO-NOT-LEAK"), json.dumps(errors))

    def test_web_client_is_access_only_and_unknown_refresh_client_is_rejected(self):
        access = token(client="web-public-client")
        parsed, errors = parse_credentials({"accessToken": access, "user": {"email": EMAIL}})
        self.assertEqual(errors, [])
        self.assertEqual(parsed[0]["client_id"], "web-public-client")
        _, errors = parse_credentials({"access_token": access, "refresh_token": "rt"})
        self.assertEqual(errors[0]["code"], "refresh_client_unsupported")

    def test_limits_and_invalid_json_have_fixed_errors(self):
        for value, code in (("{private-secret", "invalid_json"), (" " * (MAX_CONTENT_BYTES + 1), "content_too_large"),
                            ([record()] * 51, "too_many_candidates")):
            with self.subTest(code=code), self.assertRaises(CredentialImportError) as caught:
                parse_credentials(value)
            self.assertEqual(caught.exception.code, code)
            self.assertNotIn("private-secret", str(caught.exception))

    def test_duplicate_fields_and_non_finite_json_are_rejected(self):
        for value in ('{"access_token":"one","access_token":"two"}', '{"email":NaN}'):
            with self.assertRaises(CredentialImportError) as caught:
                parse_credentials(value)
            self.assertEqual(caught.exception.code, "invalid_json")

    def test_duplicate_bridge_workspace_rows_are_not_silently_overwritten(self):
        with self.assertRaises(CredentialImportError) as caught:
            parse_credentials({"email":EMAIL,"business_workspace_credentials":[
                {"workspaceId":WS,"accessToken":token()}, {"workspaceId":WS,"accessToken":token()}]})
        self.assertEqual(caught.exception.code, "duplicate_workspace")


class ImportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        service.clear_previews()
        self.temp = tempfile.TemporaryDirectory()
        self.engine = create_async_engine(f"sqlite+aiosqlite:///{Path(self.temp.name) / 'test.db'}")
        self.factory = async_sessionmaker(self.engine, expire_on_commit=False)
        async with self.engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        self.db = self.factory()

    async def asyncTearDown(self):
        await self.db.close()
        await self.engine.dispose()
        service.clear_previews()
        self.temp.cleanup()

    async def existing(self, email=EMAIL, **kwargs):
        account = Account(email=email, local_purpose="standby", operational_state="available", auth_state="healthy", **kwargs)
        self.db.add(account)
        await self.db.commit()
        return account

    async def test_preview_redacts_credentials_and_commit_preserves_pending_membership(self):
        source = record()
        self.db.add(Workspace(official_workspace_id=WS, name="Fixture", status="active"))
        await self.db.flush()
        self.db.add(WorkspaceOfficialMemberSnapshot(workspace_id=1, normalized_email=EMAIL, remote_state="invited", official_role="member", fetched_at=utcnow()))
        await self.db.commit()
        preview = await preview_import(self.db, source)
        public = json.dumps(preview)
        self.assertNotIn(source["access_token"], public)
        self.assertNotIn(source["refresh_token"], public)
        self.assertNotIn(source["access_token"].encode(), service._drafts[preview["draft_id"]]["payload"])
        self.assertEqual(await self.db.scalar(select(func.count(Account.id))), 0)
        result = await commit_import(self.db, preview["draft_id"], selected(preview))
        account = await self.db.get(Account, result["imported"][0]["account_id"])
        self.assertEqual(account.local_purpose, "standby")
        self.assertEqual(decrypt_secret(account.access_token_encrypted), source["access_token"])
        self.assertEqual(account.official_account_id, WS)
        self.assertEqual(account.credential_revision, 2)
        self.assertEqual(result["imported"][0]["verification"], "pending")
        self.assertEqual(await self.db.scalar(select(func.count(WorkspaceMembership.id))), 0)
        self.assertEqual(await self.db.scalar(select(WorkspaceOfficialMemberSnapshot.remote_state)), "invited")
        self.assertEqual(await self.db.scalar(select(func.count(QuotaSnapshot.id))), 0)
        self.assertNotIn(source["access_token"], json.dumps(result))
        self.assertFalse(service.preview_exists(preview["draft_id"]))
        with self.assertRaises(CredentialImportError) as caught:
            await commit_import(self.db, preview["draft_id"], selected(preview))
        self.assertEqual(caught.exception.code, "preview_consumed")

    async def test_at_only_replace_clears_old_bundle_but_keeps_mother_proxy_and_binding(self):
        account = await self.existing(access_token_encrypted=encrypt_secret("old-at"), refresh_token_encrypted=encrypt_secret("old-rt"),
            id_token_encrypted=encrypt_secret("old-id"), session_token_encrypted=encrypt_secret("old-session"), proxy="http://proxy.example:8080")
        account.local_purpose = "mother"
        self.db.add(Workspace(id=1, official_workspace_id=WS, owner_account_id=account.id, name="Fixture", status="active"))
        await self.db.flush()
        self.db.add(WorkspaceMembership(account_id=account.id, workspace_id=1, local_purpose="mother", official_role="owner", membership_state="joined"))
        self.db.add(ExternalBinding(provider="sub2api", local_account_id=account.id, workspace_id=1, remote_account_id="42", binding_state="verified", verified_email=EMAIL, verified_workspace_id=WS))
        await self.db.commit()
        preview = await preview_import(self.db, record(refresh_token=""))
        self.assertTrue(preview["candidates"][0]["allowed"])
        self.assertIn("将移除旧刷新凭据，之后需手动授权", preview["candidates"][0]["warnings"])
        await commit_import(self.db, preview["draft_id"], selected(preview))
        await self.db.refresh(account)
        self.assertIsNone(account.refresh_token_encrypted)
        self.assertIsNone(account.id_token_encrypted)
        self.assertIsNone(account.session_token_encrypted)
        self.assertEqual(account.local_purpose, "mother")
        self.assertEqual(account.proxy, "http://proxy.example:8080")
        self.assertEqual(await self.db.scalar(select(func.count(ExternalBinding.id))), 1)
        self.assertEqual(await self.db.scalar(select(WorkspaceMembership.official_role)), "owner")

    async def test_multiple_workspace_candidates_require_selection(self):
        preview = await preview_import(self.db, [record(), record(workspace=OTHER_WS)])
        with self.assertRaises(CredentialImportError) as caught:
            await commit_import(self.db, preview["draft_id"], selected(preview))
        self.assertEqual(caught.exception.code, "workspace_selection_required")
        result = await commit_import(self.db, preview["draft_id"], selected(preview)[1:])
        self.assertEqual(result["imported"][0]["workspace_id"], OTHER_WS)

    async def test_identity_conflict_is_blocked_but_missing_local_ids_are_supported(self):
        account = await self.existing()
        preview = await preview_import(self.db, record())
        self.assertTrue(preview["candidates"][0]["allowed"])
        account.official_account_id = OTHER_WS
        await self.db.commit()
        later = await preview_import(self.db, record())
        self.assertFalse(later["candidates"][0]["allowed"])
        self.assertEqual(later["candidates"][0]["error"]["code"], "workspace_conflict")

    async def test_compare_and_swap_credentials_and_binding_changes(self):
        account = await self.existing()
        preview = await preview_import(self.db, record())
        account.access_token_encrypted = encrypt_secret("newer-private-token")
        await self.db.commit()
        with self.assertRaises(CredentialImportError) as caught:
            await commit_import(self.db, preview["draft_id"], selected(preview))
        self.assertEqual(caught.exception.code, "account_changed")
        await self.db.refresh(account)
        self.assertEqual(decrypt_secret(account.access_token_encrypted), "newer-private-token")
        preview = await preview_import(self.db, record())
        self.db.add(ExternalBinding(provider="sub2api", local_account_id=account.id, remote_account_id="5", binding_state="pending"))
        await self.db.commit()
        with self.assertRaises(CredentialImportError) as caught:
            await commit_import(self.db, preview["draft_id"], selected(preview))
        self.assertEqual(caught.exception.code, "account_changed")

    async def test_new_account_race_and_frozen_bridge_account(self):
        preview = await preview_import(self.db, record())
        account = await self.existing()
        with self.assertRaises(CredentialImportError) as caught:
            await commit_import(self.db, preview["draft_id"], selected(preview))
        self.assertEqual(caught.exception.code, "account_changed")
        frozen = await account_snapshot(self.db, EMAIL)
        account.official_user_id = "user-change"
        await self.db.commit()
        result = await preview_import(self.db, record(), expected_email=EMAIL, expected_account=frozen)
        self.assertEqual(result["candidates"][0]["error"]["code"], "account_changed")
        absent = await preview_import(self.db, record(), expected_account={"id": None, "credential_revision": None, "fingerprint": None})
        self.assertEqual(absent["candidates"][0]["error"]["code"], "account_changed")

    async def test_remote_ownership_blocks_both_providers(self):
        account = await self.existing()
        self.db.add(CodexBinding(account_id=account.id, target_url="http://codex.example", remote_name="fixture", import_attempted=True))
        await self.db.commit()
        result = await preview_import(self.db, record())
        self.assertEqual(result["candidates"][0]["error"]["code"], "remote_refresh_owned")
        await self.db.delete(await self.db.get(CodexBinding, account.id))
        self.db.add(Sub2ApiRefreshAuthority(account_id=account.id, binding_id=1, binding_fingerprint="fingerprint", instance_id="instance", remote_account_id="1", remote_version=1, local_revision=1, local_fingerprint="fingerprint", epoch=1, last_success_at=utcnow(), last_attempt_at=utcnow()))
        await self.db.commit()
        result = await preview_import(self.db, record())
        self.assertEqual(result["candidates"][0]["error"]["code"], "remote_refresh_owned")

    async def test_busy_operation_oauth_and_refresh_lease(self):
        account = await self.existing()
        operation = Operation(public_id="fixture-op", op_type="auth_bridge_login", state="running", account_id=account.id, email=EMAIL)
        self.db.add(operation); await self.db.commit()
        result = await preview_import(self.db, record())
        self.assertEqual(result["candidates"][0]["error"]["code"], "account_busy")
        own = await preview_import(self.db, record(), ignore_operation_id=operation.id)
        self.assertTrue(own["candidates"][0]["allowed"])
        operation.state = "success"
        oauth = OAuthSession(public_id="fixture-oauth", purpose="account_reauth", mode="manual", account_id=account.id, email=EMAIL,
                             state_hash="hash", code_verifier_encrypted="encrypted", client_id=DEFAULT_OAUTH_CLIENT_ID,
                             redirect_uri="http://localhost:1455/auth/callback", authorize_url="http://fixture", status="waiting", expires_at=utcnow()+timedelta(minutes=10))
        self.db.add(oauth); await self.db.commit()
        result = await preview_import(self.db, record())
        self.assertEqual(result["candidates"][0]["error"]["code"], "account_busy")
        oauth.status="failed"
        self.db.add(CredentialLease(account_id=account.id, token="in-flight", expires_at=utcnow()+timedelta(minutes=5)))
        await self.db.commit()
        result = await preview_import(self.db, record())
        self.assertEqual(result["candidates"][0]["error"]["code"], "account_busy")

    async def test_commit_rechecks_new_busy_task_and_is_atomic(self):
        preview = await preview_import(self.db, [record(), record(email="second@example.com")])
        self.db.add(Operation(public_id="block-second", op_type="reauth", state="queued", email="second@example.com"))
        await self.db.commit()
        with self.assertRaises(CredentialImportError) as caught:
            await commit_import(self.db, preview["draft_id"], selected(preview))
        self.assertEqual(caught.exception.code, "account_busy")
        self.assertEqual(await self.db.scalar(select(func.count(Account.id))), 0)

    async def test_unknown_duplicate_and_blocked_selections_do_not_write(self):
        preview = await preview_import(self.db, record())
        for ids, code in ((["unknown"], "selection_invalid"), (selected(preview)*2, "selection_duplicate")):
            with self.assertRaises(CredentialImportError) as caught:
                await commit_import(self.db, preview["draft_id"], ids)
            self.assertEqual(caught.exception.code, code)
        self.assertEqual(await self.db.scalar(select(func.count(Account.id))), 0)

    async def test_draft_scope_expiry_discard_and_clear(self):
        preview = await preview_import(self.db, record())
        other_engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        other = async_sessionmaker(other_engine)()
        try:
            with self.assertRaises(CredentialImportError) as caught:
                await commit_import(other, preview["draft_id"], selected(preview))
            self.assertEqual(caught.exception.code, "preview_context_mismatch")
        finally:
            await other.close(); await other_engine.dispose()
        service._drafts[preview["draft_id"]]["deadline"] = time.monotonic()-1
        with self.assertRaises(CredentialImportError) as caught:
            await commit_import(self.db, preview["draft_id"], selected(preview))
        self.assertEqual(caught.exception.code, "preview_expired")
        preview = await preview_import(self.db, record())
        service.discard_preview(preview["draft_id"])
        self.assertFalse(service.preview_exists(preview["draft_id"]))
        preview = await preview_import(self.db, record())
        service.clear_previews()
        self.assertFalse(service.preview_exists(preview["draft_id"]))

    async def test_quota_verification_only_when_explicitly_requested(self):
        preview = await preview_import(self.db, record())
        with patch("app.application.quota.quota_service.enqueue", new_callable=AsyncMock) as enqueue:
            result = await commit_import(self.db, preview["draft_id"], selected(preview))
            enqueue.assert_not_awaited()
            self.assertEqual(result["verification"], [])
        preview = await preview_import(self.db, record())
        with patch("app.application.quota.quota_service.enqueue", new=AsyncMock(return_value={"ok":True,"operation_id":"fixture-check"})) as enqueue:
            result = await commit_import(self.db, preview["draft_id"], selected(preview), verify_quota=True)
            enqueue.assert_awaited_once()
            self.assertTrue(result["verification"][0]["queued"])

    async def test_preview_capacity_is_bounded(self):
        with patch.object(service, "MAX_DRAFTS", 2):
            previews = [await preview_import(self.db, record()) for _ in range(3)]
            self.assertEqual(len(service._drafts), 2)
            self.assertFalse(service.preview_exists(previews[0]["draft_id"]))

    async def test_discard_and_second_commit_cannot_race_a_processing_draft(self):
        preview = await preview_import(self.db, record())
        reached = asyncio.Event()
        resume = asyncio.Event()
        original = service._guard
        async def slow_guard(*args, **kwargs):
            reached.set()
            await resume.wait()
            return await original(*args, **kwargs)
        with patch.object(service, "_guard", slow_guard):
            task = asyncio.create_task(commit_import(self.db, preview["draft_id"], selected(preview)))
            await reached.wait()
            with self.assertRaises(CredentialImportError) as caught:
                service.discard_preview(preview["draft_id"])
            self.assertEqual(caught.exception.code, "preview_busy")
            with self.assertRaises(CredentialImportError) as caught:
                await commit_import(self.db, preview["draft_id"], selected(preview))
            self.assertEqual(caught.exception.code, "preview_busy")
            resume.set()
            self.assertEqual((await task)["count"], 1)

    async def test_mid_batch_failure_rolls_back_every_account_and_redacts_error(self):
        preview = await preview_import(self.db, [record(), record(email="second@example.com", refresh_token="trigger-private-failure")])
        original = service.encrypt_secret
        def broken(value):
            if value == "trigger-private-failure":
                raise RuntimeError("DO-NOT-LEAK-SECRET")
            return original(value)
        with patch.object(service, "encrypt_secret", broken), self.assertRaises(CredentialImportError) as caught:
            await commit_import(self.db, preview["draft_id"], selected(preview))
        self.assertEqual(caught.exception.code, "import_failed")
        self.assertNotIn("DO-NOT-LEAK-SECRET", str(caught.exception))
        self.assertEqual(await self.db.scalar(select(func.count(Account.id))), 0)

    async def test_commit_checks_token_expiry_again(self):
        preview = await preview_import(self.db, record())
        later = time.time()+7200
        with patch.object(service.time, "time", return_value=later), self.assertRaises(CredentialImportError) as caught:
            await commit_import(self.db, preview["draft_id"], selected(preview))
        self.assertEqual(caught.exception.code, "access_token_expired")
        self.assertEqual(await self.db.scalar(select(func.count(Account.id))), 0)

    async def test_quota_enqueue_failure_does_not_hide_successful_import(self):
        preview = await preview_import(self.db, record())
        with patch("app.application.quota.quota_service.enqueue", new=AsyncMock(side_effect=RuntimeError("private"))):
            result = await commit_import(self.db, preview["draft_id"], selected(preview), verify_quota=True)
        self.assertTrue(result["ok"])
        self.assertFalse(result["verification"][0]["queued"])
        self.assertNotIn("private", json.dumps(result))
        self.assertEqual(await self.db.scalar(select(func.count(Account.id))), 1)


if __name__ == "__main__":
    unittest.main()
