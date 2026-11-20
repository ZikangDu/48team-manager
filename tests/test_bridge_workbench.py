"""Native workbench contracts, with temporary SQLite and a synthetic loopback transport."""
import json
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, PropertyMock, patch

import httpx

from app.core.crypto import token_cipher
from app.integrations.auth_bridge.supervisor import BridgeSupervisor
from app.persistence.models.identity import Account, Workspace, WorkspaceMembership
from app.web.routes.bridge_workbench import EvaluationRequest, EvaluationStream, _evaluation_events
from tests.helpers import make_client
from tests.test_credential_import import token, WS


BASE = "/api/bridge-workbench/accounts"
EVAL = {"question": "candy", "model": "gpt-6-astra", "reasoning_effort": "medium"}


class FakeStream(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk

    async def aclose(self):
        self.closed = True


class WorkbenchTests(unittest.TestCase):
    def setUp(self):
        temp = self.enterContext(tempfile.TemporaryDirectory())
        self.client = self.enterContext(make_client(Path(temp), _env_file=None, auth_bridge_enabled=True))
        self.settings = self.client.app.state.settings
        self.secret = token(email="member@example.org")
        self.requests = []
        self.clients = []
        self.answer = lambda req: httpx.Response(200, json={"ok": True, "results": [{"index": 0, "status": 200}]})
        def handler(req):
            self.requests.append(req)
            return self.answer(req)
        def bridge_client():
            client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
            self.clients.append(client)
            return client
        self.enterContext(patch("app.web.routes.bridge_workbench._bridge_client", bridge_client))
        async def seed():
            cipher = token_cipher(self.settings)
            async with self.client.app.state.session_factory() as db:
                member = Account(email="member@example.org", local_purpose="child", official_plan="team",
                                 official_account_id=WS, official_user_id="user-member",
                                 access_token_encrypted=cipher.encrypt(self.secret),
                                 refresh_token_encrypted=cipher.encrypt("private-refresh-fixture"),
                                 session_token_encrypted=cipher.encrypt("private-session-fixture"))
                owner = Account(email="owner@example.org", local_purpose="mother")
                disabled = Account(email="disabled@example.org", local_purpose="disabled")
                db.add_all([member, owner, disabled])
                await db.flush()
                team = Workspace(name="Fixture", owner_account_id=owner.id, official_workspace_id=WS)
                db.add(team)
                await db.flush()
                db.add_all([WorkspaceMembership(account_id=member.id, workspace_id=team.id, official_role="member",
                                                  membership_state="joined", local_purpose="child"),
                            WorkspaceMembership(account_id=owner.id, workspace_id=team.id, official_role="unknown",
                                                  membership_state="joined", local_purpose="mother")])
                await db.commit()
                return member.id, owner.id, disabled.id, team.id
        self.member, self.owner, self.disabled, self.team = self.client.portal.call(seed)
        self.path = BASE + "/" + str(self.member)

    def login(self):
        self.assertEqual(self.client.post("/auth/login", json={"username":"hixz12","password":"test-password"}).status_code, 200)

    def update(self, id, **values):
        async def apply():
            async with self.client.app.state.session_factory() as db:
                row = await db.get(Account, id)
                for name, value in values.items():
                    setattr(row, name, value)
                await db.commit()
        self.client.portal.call(apply)

    def test_permission_metadata_and_workspaces(self):
        for method, path in [("GET", BASE), ("GET", self.path + "/workspaces"), ("POST", self.path + "/health"),
                             ("POST", self.path + "/evaluation")]:
            response = self.client.request(method, path)
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.headers["cache-control"], "no-store")
        self.login()
        rows = self.client.get(BASE).json()["accounts"]
        self.assertEqual([row["id"] for row in rows], [self.member, self.owner])
        self.assertEqual(set(rows[0]), {"id", "email", "plan", "auth_state", "purpose", "has_access_token",
                                        "has_fixed_proxy", "proxy_compatible"})
        self.assertTrue(rows[0]["has_access_token"])
        self.assertFalse(rows[1]["has_access_token"])
        expected = {"id": self.team, "name":"Fixture","state":"joined","role":"member",
                    "kind":"team","source":"registration","official_workspace_id":WS}
        self.assertEqual(self.client.get(self.path + "/workspaces").json()["workspaces"], [expected])
        expected.update(state="active", role="owner")
        self.assertEqual(self.client.get(f"{BASE}/{self.owner}/workspaces").json()["workspaces"], [expected])
        self.assertEqual(self.client.get(f"{BASE}/{self.disabled}/workspaces").status_code, 404)
        self.assertFalse(self.requests)

    def test_workspace_grant_types_filter_and_absent_grant(self):
        self.login()
        personal_id = "190e305e-b588-44dc-8955-89b0808a8020"
        endpoint = self.path + "/workspaces"
        self.update(self.member, official_account_id=personal_id)
        for plan, kind in [("plus", "personal"), ("free", "personal"), ("pro", "personal"),
                           ("business", "team"), ("team", "team"), ("unknown", "unknown"),
                           ("pro-team-trial", "unknown")]:
            with self.subTest(plan=plan):
                self.update(self.member, official_plan=plan)
                team, grant = self.client.get(endpoint).json()["workspaces"]
                self.assertEqual(team["id"], self.team)
                self.assertEqual(grant["official_workspace_id"], personal_id)
                self.assertEqual(grant["kind"], kind)
                self.assertEqual(grant["source"], "authorization")
                self.assertEqual(grant["state"], "saved")
                self.assertIsNone(grant["role"])
                self.assertIsNone(grant["id"])
                filtered = self.client.get(endpoint, params={"skip_personal":"true"}).json()["workspaces"]
                self.assertEqual(filtered, [team] if kind == "personal" else [team, grant])
        self.update(self.member, official_account_id="user-legacy", official_plan="free")
        self.assertEqual(len(self.client.get(endpoint).json()["workspaces"]), 1)
        self.update(self.member, official_account_id=personal_id, access_token_encrypted=None)
        self.assertEqual(len(self.client.get(endpoint).json()["workspaces"]), 1)
        self.assertFalse(self.requests)

    def test_removed_seat_and_stale_grant_do_not_recreate_workspace(self):
        from sqlalchemy import update
        async def remove_membership():
            async with self.client.app.state.session_factory() as db:
                await db.execute(update(WorkspaceMembership).where(
                    WorkspaceMembership.account_id == self.member).values(membership_state="removed"))
                await db.commit()
        self.login()
        self.client.portal.call(remove_membership)
        self.update(self.member, official_plan="free")
        for skip_personal in ["false", "true"]:
            rows = self.client.get(self.path + "/workspaces", params={"skip_personal":skip_personal}).json()["workspaces"]
            self.assertEqual(rows, [])
        self.assertFalse(self.requests)

    def test_list_uses_the_selected_import_and_omits_unselected_candidates(self):
        self.login()
        email = "new-personal@example.org"
        personal_id = "54a0403c-0d63-4231-9a0b-2f8c3df141b0"
        claims = {"chatgpt_account_id": personal_id, "chatgpt_user_id": "user-member", "chatgpt_plan_type": "plus"}
        personal = token(email=email, workspace=personal_id, **{"https://api.openai.com/auth": claims})
        preview = self.client.post("/api/credential-import/preview", json={"content": [
            {"access_token": token(email=email)}, {"access_token": personal}]}).json()
        choice = next(row for row in preview["candidates"] if row["workspace_id"] == personal_id)
        result = self.client.post("/api/credential-import/commit", json={
            "draft_id": preview["draft_id"], "selected_ids": [choice["id"]]}).json()
        endpoint = f"{BASE}/{result['imported'][0]['account_id']}/workspaces"
        self.assertEqual(self.client.get(endpoint).json()["workspaces"], [{
            "id": None, "name": "个人空间", "official_workspace_id": personal_id,
            "kind": "personal", "source": "authorization", "state": "saved", "role": None}])
        self.assertEqual(self.client.get(endpoint, params={"skip_personal":True}).json()["workspaces"], [])
        self.assertFalse(self.requests)

    def test_health_limits_credentials_and_filters_output(self):
        self.login()
        def answer(req):
            self.assertEqual(self.client.app.state.engine.pool.checkedout(), 0)
            return httpx.Response(200, json={"ok":True, "results":[{
            "index":0, "status":200, "error":self.secret, "cookies":"private-session-fixture",
            "usage":{"fiveHour":{"usedPercent":0, "resetAt":1893456000}, "sevenDay":{"usedPercent":25.5, "resetAfterSeconds":60},
                     "fetchedAt":1893456000000},
            "devicesStatus":200, "deviceCount":2, "devices":[{"location":"private-location"},{}],
            "appSessionCount":3, "firstLoginAt":1893456000500, "lastLoginAt":1893456030000,
            }]})
        self.answer = answer
        response = self.client.post(self.path + "/health", json={})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["healthy"])
        self.assertEqual(response.json()["quota"], {"five_hour_used_percent": 0, "seven_day_used_percent": 25.5,
                                                    "five_hour_resets_at":"2030-01-01T00:00:00+00:00",
                                                    "seven_day_resets_at":"2030-01-01T00:01:00+00:00"})
        self.assertIsNotNone(datetime.fromisoformat(response.json()["checked_at"]).tzinfo)
        self.assertEqual(response.json()["device_count"], 2)
        self.assertEqual(response.json()["app_session_count"], 3)
        self.assertEqual(response.json()["first_login_at"], "2030-01-01T00:00:00.500000+00:00")
        self.assertEqual(response.json()["last_login_at"], "2030-01-01T00:00:30+00:00")
        self.assertNotIn(self.secret, response.text)
        self.assertNotIn("private-", response.text)
        req = self.requests.pop()
        self.assertEqual(str(req.url), "http://127.0.0.1:4174/api/session-health")
        body = json.loads(req.content)
        self.assertTrue(body["includeDevices"])
        self.assertFalse(body["includeTrial"])
        self.assertEqual(body["accounts"], [{"accessToken":self.secret, "accountId":WS,"planType":"team"}])
        self.assertNotIn("cookie", req.headers)
        self.assertNotIn("authorization", req.headers)
        self.assertTrue(self.clients[-1].is_closed)
        self.answer = lambda req: httpx.Response(200, json={"ok":True,"results":[{"index":0,"status":401}]})
        result = self.client.post(self.path + "/health", json={}).json()
        self.assertFalse(result["healthy"])
        self.assertEqual(result["status"], 401)
        self.assertIsNone(result["device_count"])
        self.answer = lambda req: httpx.Response(200, json={"ok":True,"results":[{"index":0,"status":200}]})
        self.assertFalse(self.client.post(self.path + "/health", json={}).json()["healthy"])

    def test_partial_device_results_and_legacy_bridge(self):
        self.login()
        sample = {"index": 0, "status": 200, "usage": {"fiveHour": {"usedPercent": 0}}}
        oldest = "2029-12-31T16:00:00+00:00"
        latest = "2030-01-01T00:01:00+00:00"
        cases = [
            ({"devicesStatus":403, "deviceCount":7, "appSessionCount":12, "lastLoginAt":1893456060000},
             (403, None, None, None, None)),
            ({"devicesStatus":200, "deviceCount":2, "devices":[
                {"createdAt":"2030-01-01T00:00:00+08:00", "lastLoginAt":"1893456060", "apps":["chat","chat"]},
                {"createdAt":1893456060000, "lastLoginAt":"invalid", "apps":[]}]},
             (200, 2, None, oldest, latest)),
            ({"devicesStatus":200, "deviceCount":0, "devices":[], "appSessionCount":0, "firstLoginAt":1893456060000},
             (200, 0, 0, None, None)),
            ({"devicesStatus":200, "deviceCount":1, "devices":[], "appSessionCount":3},
             (200, None, None, None, None)),
            ({"devicesStatus":200, "deviceCount":1, "firstLoginAt":"2030-01-01", "lastLoginAt":False},
             (200, 1, None, None, None)),
            ({"status":401, "devicesStatus":200, "deviceCount":1, "appSessionCount":0},
             (None, None, None, None, None)),
        ]
        for device_fields, expected in cases:
            with self.subTest(fields=device_fields):
                row = {**sample, **device_fields}
                self.answer = lambda req: httpx.Response(200, json={"ok":True, "results":[row]})
                response = self.client.post(self.path + "/health", json={})
                self.assertEqual(response.status_code, 200)
                result = response.json()
                self.assertEqual(result["healthy"], row["status"] == 200)
                self.assertEqual(tuple(result[key] for key in ("devices_status","device_count","app_session_count",
                                                               "first_login_at","last_login_at")), expected)
                self.assertNotIn("devices", result)
                self.assertNotIn("session_count", result)

    def test_rejects_origin_inputs_identity_and_bad_bridge(self):
        self.login()
        for path, body, headers, expected in [
            ("health",{},{"origin":"https://invalid.example"},403),
            ("health",{"token":self.secret},{},400),
            ("evaluation",{**EVAL,"api":{"baseUrl":"https://example.org"}},{},400),
            ("evaluation",{**EVAL,"reasoning_effort":"ultra"},{},400),
        ]:
            response = self.client.post(self.path + "/" + path, json=body, headers=headers)
            self.assertEqual(response.status_code, expected)
            self.assertNotIn(self.secret, response.text)
            self.assertEqual(response.headers["cache-control"], "no-store")
        self.settings.auth_bridge_url = "https://invalid.example"
        response = self.client.post(self.path + "/health", json={})
        self.assertEqual(response.status_code, 503)
        self.settings.auth_bridge_url = "http://127.0.0.1:4174"
        self.update(self.member, official_user_id="different")
        self.assertEqual(self.client.post(self.path + "/health", json={}).status_code, 409)
        self.assertEqual(self.client.post(self.path + "/evaluation", json=EVAL).status_code, 409)
        self.update(self.member, official_user_id="user-member", email="wrong@example.org")
        self.assertEqual(self.client.post(self.path + "/health", json={}).status_code, 409)
        self.assertEqual(self.client.post(f"{BASE}/{self.owner}/health", json={}).status_code, 409)
        self.assertFalse(self.requests)

    def test_inherited_pinned_proxy_and_only_proven_compatible_exit(self):
        self.login()
        proxy = "http://fixture-user:fixture-password@routing.invalid:8124"
        self.update(self.owner, proxy=proxy)
        rows = self.client.get(BASE)
        self.assertNotIn("fixture-password", rows.text)
        self.assertTrue(all(row["has_fixed_proxy"] and not row["proxy_compatible"] for row in rows.json()["accounts"]))
        self.assertEqual(self.client.post(self.path + "/health", json={}).status_code, 409)
        self.settings.auth_bridge_managed = True
        runtime = BridgeSupervisor()
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"TEAM48_BRIDGE_OPENAI_PROXY_URL":proxy}), \
                patch.object(BridgeSupervisor,"bundled",new_callable=PropertyMock,return_value=True), \
                patch.object(runtime,"find_node",return_value="test-node"), \
                patch.object(runtime,"_healthy",new=AsyncMock(side_effect=[False,True])), \
                patch("app.integrations.auth_bridge.supervisor.subprocess.Popen") as popen, \
                patch("app.web.routes.bridge_workbench.bridge_supervisor",runtime):
            popen.return_value.poll.return_value = None
            async def start():
                return await runtime.start(port=4174, runtime_dir=Path(temp), python="test-python",
                    yescaptcha_api_key="fixture-client-key", yescaptcha_api_base_url="https://solver.invalid",
                    turnstile_sitekey="fixture-sitekey")
            self.assertEqual(self.client.portal.call(start), "running")
            child_env = popen.call_args.kwargs["env"]
            self.assertEqual(child_env["YESCAPTCHA_API_KEY"], "fixture-client-key")
            self.assertEqual(child_env["YESCAPTCHA_API_BASE_URL"], "https://solver.invalid")
            self.assertEqual(child_env["OPENAI_TURNSTILE_SITEKEY"], "fixture-sitekey")
            self.addCleanup(runtime._log.close)
            self.assertTrue(self.client.get(BASE).json()["accounts"][0]["proxy_compatible"])
            self.assertEqual(self.client.post(self.path + "/health", json={}).status_code, 200)
            self.assertFalse(runtime.uses_fixed_proxy("http://127.0.0.1:4174", proxy + "x"))
            self.assertFalse(runtime.uses_fixed_proxy("http://127.0.0.1:4111", proxy))
            popen.return_value.poll.return_value = 1
            self.assertFalse(self.client.get(BASE).json()["accounts"][0]["proxy_compatible"])
        self.assertEqual(len(self.requests), 1)

    def test_streams_real_events_and_rejects_interrupted_stream(self):
        self.login()
        frames = [": heartbeat\n\n", 'data: {"type":"phase","phase":"waiting"}\n\n',
                  'data: {"type":"delta","delta":"answer","durationMs":25}\n\n',
                  'data: {"type":"complete","status":"passed","answer":"21","output":"answer","outputTokens":3,"token":"private"}\n\n']
        stream = FakeStream([x.encode() for x in frames])
        def answer(req):
            self.assertEqual(self.client.app.state.engine.pool.checkedout(), 0)
            return httpx.Response(200, headers={"content-type":"text/event-stream"}, stream=stream)
        self.answer = answer
        response = self.client.post(self.path + "/evaluation", json=EVAL)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers["content-type"].startswith("text/event-stream"))
        self.assertEqual(response.headers["x-accel-buffering"], "no")
        self.assertIn(": heartbeat", response.text)
        self.assertNotIn("private", response.text)
        self.assertNotIn(self.secret, response.text)
        events = [json.loads(line[5:]) for line in response.text.splitlines() if line.startswith("data:")]
        self.assertEqual([e["type"] for e in events], ["phase", "delta", "complete"])
        self.assertEqual(events[-1]["outputTokens"], 3)
        self.assertEqual(str(self.requests[-1].url), "http://127.0.0.1:4174/api/model-evaluation")
        self.assertTrue(stream.closed and self.clients[-1].is_closed)
        for bad in [b'data: {"type":"delta","delta":"part"}\n\n', b'data: null\n\n',
                    b'data: {"type":"error","error":"private-upstream"}\n\n']:
            self.answer = lambda req: httpx.Response(200, headers={"content-type":"text/event-stream"}, content=bad)
            response = self.client.post(self.path + "/evaluation", json=EVAL)
            self.assertIn('"type": "error"', response.text)
            self.assertNotIn("private-upstream", response.text)

    def test_disconnecting_stream_closes_upstream(self):
        stream = FakeStream([b'data: {"type":"phase","phase":"queued"}\n\n', b': heartbeat\n\n'])
        self.answer = lambda req: httpx.Response(200, headers={"content-type":"text/event-stream"}, stream=stream)
        async def probe():
            events = _evaluation_events("http://127.0.0.1:4174", {"accessToken":self.secret}, EvaluationRequest(**EVAL))
            async def disconnected_send(message):
                if message["type"] == "http.response.body":
                    self.assertIn(b"queued", message["body"])
                    raise OSError("fixture browser disconnected")
            with self.assertRaises(OSError):
                await EvaluationStream(events).stream_response(disconnected_send)
        self.client.portal.call(probe)
        self.assertTrue(stream.closed and self.clients[-1].is_closed)

    def test_bad_health_response_and_downstream_connection_errors_are_redacted(self):
        self.login()
        for reply, expected in [(httpx.Response(302, headers={"Location":"https://invalid.example"}),502),
                                (httpx.Response(429, text=self.secret),429),
                                (httpx.Response(200, json={"ok":True,"results":[{"index":1,"status":200}]}),502)]:
            self.answer = lambda req: reply
            response = self.client.post(self.path + "/health", json={})
            self.assertEqual(response.status_code, expected)
            self.assertNotIn(self.secret, response.text)
            self.assertTrue(self.clients[-1].is_closed)
        def disconnected(req):
            raise httpx.ConnectError(self.secret)
        self.answer = disconnected
        response = self.client.post(self.path + "/health", json={})
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(self.secret, response.text)
        self.assertTrue(self.clients[-1].is_closed)
