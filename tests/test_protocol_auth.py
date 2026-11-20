"""Offline contracts for browser-free protocol auth: Bridge client, HTTP MFA transport, orchestration.

No network, no real Bridge, no real account. The Bridge is an httpx MockTransport
and curl_cffi is monkeypatched; credential import runs against a temp SQLite db.
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.main  # noqa: F401 - register every model
from app.integrations.auth_bridge.login_client import BridgeError, BridgeLoginClient, normalize_bridge_url
from app.integrations.openai.mfa import MfaTransportError
from app.integrations.openai.mfa_http import HttpSessionTransport, _cookies_from_storage
from app.application import protocol_auth
from app.application.protocol_auth import ProtocolAuthError, parse_account_lines
from app.persistence.database import Base
from app.persistence.models.identity import Account
from tests.test_credential_import import token, WS

EMAIL = "member@example.com"
STORAGE = json.dumps({"cookies": [
    {"name": "session-token", "value": "cookie-session", "domain": ".chatgpt.com"},
    {"name": "oai-did", "value": "device-abc-123456", "domain": "chatgpt.com"},
    {"name": "cf_clearance", "value": "cf-xyz", "domain": ".chatgpt.com"},
    {"name": "unrelated", "value": "nope", "domain": "example.com"},
]})


class LineParsingTests(unittest.TestCase):
    def test_separators_optional_totp_and_errors(self):
        rows = parse_account_lines(
            "a@example.com----pass1----JBSWY3DPEHPK3PXP\n"
            "b@example.com——pa--ss——KRSXG5DSNFXGOIDB\n"       # em-dash separators, dashes inside password
            "c@example.com|pass3|\n"                              # pipe, no 2FA
            "# comment\n   \n"
            "d@example.com----pass4")
        self.assertEqual([r["email"] for r in rows], ["a@example.com", "b@example.com", "c@example.com", "d@example.com"])
        self.assertEqual(rows[1]["password"], "pa--ss")
        self.assertEqual(rows[1]["totp"], "KRSXG5DSNFXGOIDB")
        self.assertEqual((rows[2]["totp"], rows[3]["totp"]), ("", ""))

    def test_rejections(self):
        for text, code in [("", "input_empty"), ("not-an-account", "line_invalid"),
                           ("a@example.com", "line_invalid"), ("a@example.com----", "line_invalid"),
                           ("a@example.com----p----not-base32!", "line_invalid"),
                           ("a@example.com----p\na@example.com----q", "line_duplicate")]:
            with self.subTest(code=code):
                with self.assertRaises(ProtocolAuthError) as caught:
                    parse_account_lines(text)
                self.assertEqual(caught.exception.code, code)

    def test_too_many(self):
        with self.assertRaises(ProtocolAuthError) as caught:
            parse_account_lines("\n".join(f"u{i}@example.com----p" for i in range(protocol_auth.MAX_LINES + 1)))
        self.assertEqual(caught.exception.code, "too_many")


class BridgeUrlTests(unittest.TestCase):
    def test_only_loopback_http_with_port(self):
        self.assertEqual(normalize_bridge_url("http://127.0.0.1:4173"), "http://127.0.0.1:4173")
        self.assertEqual(normalize_bridge_url("http://localhost:4173/"), "http://127.0.0.1:4173")
        for bad in ("https://127.0.0.1:4173", "http://evil.example:80", "http://127.0.0.1",
                    "http://user@127.0.0.1:4173", "http://127.0.0.1:4173/path", "http://127.0.0.1:4173?x=1"):
            with self.subTest(bad=bad):
                with self.assertRaises(BridgeError):
                    normalize_bridge_url(bad)


class HttpTransportTests(unittest.IsolatedAsyncioTestCase):
    def test_cookie_and_device_extraction(self):
        cookies, device = _cookies_from_storage(STORAGE)
        self.assertEqual(device, "device-abc-123456")
        self.assertIn("session-token", cookies)
        self.assertNotIn("unrelated", cookies)       # other origins are dropped
        self.assertEqual(_cookies_from_storage("not json"), ({}, ""))

    async def test_path_guard_blocks_cross_origin_and_bad_methods(self):
        transport = HttpSessionTransport(storage_state_json=STORAGE, proxy="http://127.0.0.1:1")
        for method, path in [("GET", "/backend-api/accounts/mfa_info"), ("POST", "/a/b")]:
            self.assertIsNotNone(path)
        for method, path in [("PUT", "/x"), ("GET", "evil"), ("GET", "//evil.example/x"),
                             ("GET", "/\\evil.example/x"), ("GET", "/a b"), ("GET", "/x?y")]:
            with self.subTest(path=path):
                with self.assertRaises(MfaTransportError):
                    await transport.request(method, path, headers={}, body=None)

    async def test_request_adds_transport_headers_and_returns_status_text(self):
        seen = {}

        def fake_send(method, url, headers, body):
            seen.update(method=method, url=url, headers=dict(headers), body=body)
            return 200, '{"ok": true}'

        transport = HttpSessionTransport(storage_state_json=STORAGE, proxy="http://127.0.0.1:1", locale="zh-CN")
        with patch.object(transport, "_send", fake_send):
            status, text = await transport.request("GET", "/backend-api/accounts/mfa_info",
                                                   headers={"authorization": "Bearer T"}, body=None)
        self.assertEqual((status, text), (200, '{"ok": true}'))
        self.assertEqual(seen["url"], "https://chatgpt.com/backend-api/accounts/mfa_info")
        self.assertEqual(seen["headers"]["oai-device-id"], "device-abc-123456")
        self.assertEqual(seen["headers"]["oai-language"], "zh-CN")
        self.assertEqual(seen["headers"]["origin"], "https://chatgpt.com")
        self.assertEqual(seen["headers"]["authorization"], "Bearer T")

    async def test_transport_failure_is_mfa_transport_error(self):
        transport = HttpSessionTransport(storage_state_json=STORAGE)
        with patch.object(transport, "_send", side_effect=RuntimeError("boom")):
            with self.assertRaises(MfaTransportError):
                await transport.request("GET", "/backend-api/accounts/mfa_info", headers={}, body=None)


def _bridge_mock(handler):
    return BridgeLoginClient("http://127.0.0.1:4173", transport=httpx.MockTransport(handler))


class BridgeClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_status_validates_service_and_concurrency(self):
        def handler(request):
            if request.url.path == "/api/health":
                return httpx.Response(200, json={"ok": True, "service": "email-server"})
            return httpx.Response(200, json={"ok": True, "taskConcurrency": 10, "totpResetProtocolVersion": 2})
        status = await _bridge_mock(handler).status()
        self.assertEqual((status["task_concurrency"], status["totp_reset_version"]), (10, 2))

    async def test_status_rejects_wrong_service(self):
        client = _bridge_mock(lambda r: httpx.Response(200, json={"ok": True, "service": "something-else"})
                              if r.url.path == "/api/health" else httpx.Response(200, json={"ok": True, "taskConcurrency": 10}))
        with self.assertRaises(BridgeError) as caught:
            await client.status()
        self.assertEqual(caught.exception.code, "bridge_incompatible")

    async def test_login_batch_maps_ok_and_failure_rows(self):
        def handler(request):
            body = json.loads(request.content)
            self.assertEqual(body["workspaceMode"], "all")
            accounts = [{"id": "a0", "email": "ok@example.com", "openai_access_token": token("ok@example.com"),
                         "openai_rt": "rt-ok", "business_workspace_credentials": []},
                        {"id": "a1", "email": "bad@example.com"}]
            results = [{"id": "a0", "email": "ok@example.com", "ok": True},
                       {"id": "a1", "email": "bad@example.com", "ok": False, "validationFailure": {"code": "INVALID_PASSWORD"}}]
            return httpx.Response(200, json={"browserState": {"accounts": accounts}, "results": results})
        rows = await _bridge_mock(handler).login_batch(
            [{"id": "a0", "email": "ok@example.com", "openai_password": "p", "two_factor_secret": ""},
             {"id": "a1", "email": "bad@example.com", "openai_password": "p", "two_factor_secret": ""}],
            proxy="", concurrency=2)
        self.assertEqual(rows[0]["ok"], True)
        self.assertEqual(rows[0]["account"]["openai_access_token"], token("ok@example.com"))
        self.assertEqual((rows[1]["ok"], rows[1]["code"]), (False, "bridge_credentials_rejected"))

    async def test_login_batch_rejects_identity_swap(self):
        def handler(request):
            return httpx.Response(200, json={
                "browserState": {"accounts": [{"id": "a0", "email": "other@example.com", "openai_access_token": "x"}]},
                "results": [{"id": "a0", "email": "ok@example.com", "ok": True}]})
        rows = await _bridge_mock(handler).login_batch(
            [{"id": "a0", "email": "ok@example.com", "openai_password": "p", "two_factor_secret": ""}], proxy="")
        self.assertEqual((rows[0]["ok"], rows[0]["code"]), (False, "bridge_identity_mismatch"))

    async def test_login_web_session_returns_token_and_storage(self):
        def handler(request):
            self.assertEqual(json.loads(request.content)["workspaceMode"], "session")
            return httpx.Response(200, json={"browserState": {"accounts": [
                {"id": "team48-session", "email": EMAIL, "session_access_token": "sess-tok", "storage_state_json": STORAGE}]},
                "results": [{"id": "team48-session", "email": EMAIL, "ok": True}]})
        session = await _bridge_mock(handler).login_web_session(email=EMAIL, password="p", totp_secret="JBSWY3DPEHPK3PXP")
        self.assertEqual(session["session_access_token"], "sess-tok")
        self.assertIn("oai-did", session["storage_state_json"])

    async def test_login_web_session_failure_is_coded(self):
        def handler(request):
            return httpx.Response(200, json={"browserState": {"accounts": [{"id": "team48-session", "email": EMAIL}]},
                                             "results": [{"id": "team48-session", "email": EMAIL, "ok": False,
                                                          "terminalReason": "ACCOUNT_DEACTIVATED"}]})
        with self.assertRaises(BridgeError) as caught:
            await _bridge_mock(handler).login_web_session(email=EMAIL, password="p", totp_secret="JBSWY3DPEHPK3PXP")
        self.assertEqual(caught.exception.code, "bridge_account_unavailable")


class ImportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_async_engine("sqlite+aiosqlite:///" + str(Path(self.tmp.name) / "t.db"))
        async with self.engine.begin() as c:
            await c.run_sync(Base.metadata.create_all)
        self.factory = async_sessionmaker(self.engine, expire_on_commit=False)

    async def asyncTearDown(self):
        await self.engine.dispose()
        self.tmp.cleanup()

    async def test_personal_credential_is_imported(self):
        account = {"email": EMAIL, "openai_access_token": token(EMAIL), "openai_rt": "rt-ok",
                   "openai_id_token": "", "openai_account_id": WS, "business_workspace_credentials": []}
        async with self.factory() as db:
            status = await protocol_auth._import_account(db, EMAIL, account)
            await db.commit()
        self.assertEqual(status, "imported")
        async with self.factory() as db:
            row = await db.scalar(select(Account).where(func.lower(Account.email) == EMAIL))
        self.assertIsNotNone(row)
        self.assertTrue(row.refresh_token_encrypted and row.access_token_encrypted)

    async def test_no_personal_credential_reports_no_credential(self):
        async with self.factory() as db:
            status = await protocol_auth._import_account(db, EMAIL, {"email": EMAIL, "business_workspace_credentials": []})
        self.assertEqual(status, "no_credential")


if __name__ == "__main__":
    unittest.main()
