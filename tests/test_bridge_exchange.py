"""Selected Bridge exports use synthetic credentials and a temporary local database."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.core.crypto import token_cipher
from app.integrations.auth_bridge.credentials import CredentialImportError
from app.persistence.models.identity import Account
from tests.helpers import make_client
from tests.test_credential_import import token, WS, OTHER_WS

PATH = "/api/bridge-workbench/accounts/export"


class BridgeExchangeTests(unittest.TestCase):
    def setUp(self):
        temp = self.enterContext(tempfile.TemporaryDirectory())
        self.client = self.enterContext(make_client(Path(temp), _env_file=None))
        self.cipher = token_cipher(self.client.app.state.settings)
        self.access = token(email="selected@example.test", exp=100)
        self.identity = token(email="selected@example.test")

        async def seed():
            async with self.client.app.state.session_factory() as db:
                selected = Account(email="selected@example.test", official_account_id=WS, official_user_id="user-member",
                    official_plan="team", local_purpose="child", access_token_encrypted=self.cipher.encrypt(self.access),
                    refresh_token_encrypted=self.cipher.encrypt("fixture-refresh"),
                    id_token_encrypted=self.cipher.encrypt(self.identity),
                    session_token_encrypted=self.cipher.encrypt("fixture-session"),
                    password_encrypted=self.cipher.encrypt("fixture-password-must-stay-local"),
                    proxy="http://fixture-proxy-secret@proxy.example.test:8888")
                other = Account(email="other@example.test", local_purpose="child",
                    access_token_encrypted=self.cipher.encrypt(token(email="other@example.test")),
                    refresh_token_encrypted=self.cipher.encrypt("fixture-unselected-refresh"))
                empty = Account(email="empty@example.test", local_purpose="standby")
                disabled = Account(email="disabled@example.test", local_purpose="disabled")
                archived = Account(email="archived@example.test", local_purpose="child", operational_state="archived")
                db.add_all([selected, other, empty, disabled, archived])
                await db.commit()
                return selected.id, other.id, empty.id, disabled.id, archived.id

        self.selected, self.other, self.empty, self.disabled, self.archived = self.client.portal.call(seed)

    def login(self):
        self.assertEqual(self.client.post("/auth/login", json={"username": "hixz12", "password": "test-password"}).status_code, 200)

    def export(self, ids=None, **kwargs):
        return self.client.post(PATH, json={"account_ids": ids or [self.selected], "confirm": True}, **kwargs)

    def update(self, **values):
        async def apply():
            async with self.client.app.state.session_factory() as db:
                selected = await db.get(Account, self.selected)
                for name, value in values.items():
                    setattr(selected, name, value)
                await db.commit()
        self.client.portal.call(apply)

    def private(self, response):
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["pragma"], "no-cache")

    def test_exports_only_explicitly_selected_complete_credentials(self):
        response = self.export()
        self.assertEqual(response.status_code, 401)
        self.private(response)
        self.login()
        response = self.export([self.selected, self.selected])
        self.assertEqual(response.status_code, 200)
        self.private(response)
        self.assertEqual(response.json(), {"ok": True, "count": 1, "accounts": [{
            "email": "selected@example.test", "accessToken": self.access, "refresh_token": "fixture-refresh",
            "id_token": self.identity, "sessionToken": "fixture-session",
            "user": {"email": "selected@example.test", "id": "user-member"},
            "account": {"id": WS, "planType": "team"}}]})
        for private in ("fixture-password-must-stay-local", "fixture-proxy-secret", "fixture-unselected-refresh", "other@example.test"):
            self.assertNotIn(private, response.text)
        self.assertNotIn("2fa", response.text.lower())

    def test_confirmation_ids_origin_and_body_guards(self):
        self.login()
        for data in ({"account_ids": [self.selected]}, {"account_ids": [self.selected], "confirm": 1},
                     {"account_ids": [self.selected], "confirm": False}, {"account_ids": [True], "confirm": True},
                     {"account_ids": [1.0], "confirm": True}, {"account_ids": [], "confirm": True},
                     {"account_ids": list(range(1, 52)), "confirm": True},
                     {"account_ids": [self.selected], "confirm": True, "password": "fixture-input-secret"}):
            response = self.client.post(PATH, json=data)
            self.assertEqual(response.status_code, 400, data)
            self.assertNotIn("fixture-input-secret", response.text)
            self.private(response)
        self.assertEqual(self.client.post(PATH, content="fixture-raw").status_code, 415)
        for headers in ({"origin": "https://elsewhere.test"}, {"sec-fetch-site": "cross-site"}, {"sec-fetch-site": "same-site"}):
            response = self.export(headers=headers)
            self.assertEqual(response.status_code, 403)
            self.private(response)

    def test_missing_archived_disabled_and_corrupt_records_are_atomic(self):
        self.login()
        for account_id in (999999, self.empty, self.archived, self.disabled):
            response = self.export([self.selected, account_id])
            self.assertEqual(response.status_code, 409)
            self.assertNotIn(self.access, response.text)
            self.assertNotIn("fixture-refresh", response.text)
            self.private(response)
        self.update(access_token_encrypted="fixture-invalid-ciphertext")
        response = self.export()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["detail"]["error_code"], "credential_unavailable")
        self.assertNotIn("fixture-invalid-ciphertext", response.text)
        self.update(access_token_encrypted=self.cipher.encrypt(self.access))
        with patch("app.web.routes.bridge_exchange.parse_credentials", side_effect=CredentialImportError("content_too_large", "fixture-private-detail")):
            response = self.export()
        self.assertEqual(response.status_code, 409)
        self.assertNotIn("fixture-private-detail", response.text)

    def test_conflicting_email_workspace_user_or_id_token_rejects_all_tokens(self):
        self.login()
        for values in ({"email": "mismatch@example.test"}, {"official_account_id": OTHER_WS},
                       {"official_user_id": "different-user"}, {"id_token_encrypted": self.cipher.encrypt(token(email="other@example.test"))}):
            with self.subTest(values=tuple(values)):
                self.update(**values)
                response = self.export()
                self.assertEqual(response.status_code, 409)
                self.assertEqual(response.json()["detail"]["error_code"], "credential_identity_mismatch")
                self.assertNotIn(self.access, response.text)
                self.assertNotIn("fixture-session", response.text)
                self.update(email="selected@example.test", official_account_id=WS, official_user_id="user-member",
                    id_token_encrypted=self.cipher.encrypt(self.identity))

    def test_normalized_tokens_and_unknown_plan_use_local_profile(self):
        self.login()
        unknown = token(email="selected@example.test", exp=100, **{
            "https://api.openai.com/auth": {"chatgpt_account_id": WS, "chatgpt_user_id": "user-member"}})
        self.update(access_token_encrypted=self.cipher.encrypt("  " + unknown + "  "),
            id_token_encrypted=None, refresh_token_encrypted=self.cipher.encrypt("  fixture-refresh  "))
        response = self.export()
        self.assertEqual(response.status_code, 200)
        record = response.json()["accounts"][0]
        self.assertEqual(record["accessToken"], unknown)
        self.assertEqual(record["refresh_token"], "fixture-refresh")
        self.assertEqual(record["account"]["planType"], "team")

    def test_auto_save_requires_admin_and_same_origin_and_returns_no_secrets(self):
        path = "/api/bridge-workbench/authorizations/auto-save"
        body = {"accounts": [{"email": "new@example.test", "access_token": token(email="new@example.test"),
                              "refresh_token": "fixture-auto-refresh"}]}
        self.assertEqual(self.client.post(path, json=body).status_code, 401)
        self.login()
        self.assertEqual(self.client.post(path, json=body, headers={"origin": "https://other.test"}).status_code, 403)
        response = self.client.post(path, json=body)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["saved"], 1)
        self.assertNotIn("fixture-auto-refresh", response.text)
        self.assertNotIn(body["accounts"][0]["access_token"], response.text)
        self.private(response)
        repeated = self.client.post(path, json=body)
        self.assertEqual(repeated.json()["results"][0]["status"], "unchanged")

    def test_proxy_options_are_private_and_never_return_proxy_credentials(self):
        path = "/api/protocol-auth/options"
        self.assertEqual(self.client.get(path).status_code, 401)
        self.login()
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        self.private(response)
        self.assertNotIn("fixture-proxy-secret", response.text)

    def test_authorization_progress_is_private_admin_only_and_local(self):
        path = f"/api/bridge-workbench/authorizations/{self.selected}/status"
        self.assertEqual(self.client.get(path).status_code, 401)
        self.login()
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        self.private(response)
        self.assertNotIn(self.access, response.text)
        self.assertNotIn("fixture-refresh", response.text)
        self.assertEqual(self.client.get("/api/bridge-workbench/authorizations/999999/status").status_code, 404)


if __name__ == "__main__":
    unittest.main()
