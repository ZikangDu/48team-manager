"""The original Bridge UI runs behind a fixed authenticated loopback boundary."""
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import anyio
import httpx
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.middleware.sessions import SessionMiddleware

from app.web.routes.bridge_embed import build_bridge_embed_router, _safe_path, _upstream


class TrackedStream(httpx.AsyncByteStream):
    def __init__(self, data):
        self.data = data
        self.closed = False

    async def __aiter__(self):
        for part in self.data:
            yield part

    async def aclose(self):
        self.closed = True


def app_fixture():
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="isolated-embed-fixture")
    app.state.settings = SimpleNamespace(auth_bridge_enabled=True, auth_bridge_url="http://127.0.0.1:4174")

    @app.post("/fixture/login")
    async def login(request: Request):
        request.session["user"] = {"is_admin": True}
        return {"ok": True}

    app.include_router(build_bridge_embed_router())
    return app


class EmbedGatewayTests(unittest.TestCase):
    def setUp(self):
        self.app = app_fixture()
        self.client = self.enterContext(TestClient(self.app))
        self.requests = []
        self.clients = []
        self.streams = []
        self.answer = lambda req: httpx.Response(200, json={"ok": True})

        def handler(request):
            self.requests.append(request)
            return self.answer(request)

        def upstream_client():
            client = httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False, follow_redirects=False)
            self.clients.append(client)
            return client

        self.enterContext(patch("app.web.routes.bridge_embed._new_bridge_client", upstream_client))

    def login(self):
        self.assertEqual(self.client.post("/fixture/login").status_code, 200)

    def private(self, response):
        self.assertEqual(response.headers.get("cache-control"), "no-store")
        self.assertEqual(response.headers.get("pragma"), "no-cache")
        self.assertEqual(response.headers.get("referrer-policy"), "no-referrer")

    def test_all_endpoints_are_admin_only_and_readiness_is_bounded(self):
        for path in ("/auth-bridge", "/auth-bridge/", "/auth-bridge/app.js", "/auth-bridge/api/v2/accounts"):
            response = self.client.get(path, follow_redirects=False)
            self.assertEqual(response.status_code, 401)
            self.private(response)
        self.assertFalse(self.requests)
        self.login()
        self.app.state.settings.auth_bridge_enabled = False
        response = self.client.get("/auth-bridge/")
        self.assertEqual(response.status_code, 503)
        self.private(response)
        self.assertFalse(self.requests)
        self.app.state.settings.auth_bridge_enabled = True
        self.app.state.settings.auth_bridge_url = "https://elsewhere.example.test/"
        response = self.client.get("/auth-bridge/")
        self.assertEqual(response.status_code, 503)
        self.private(response)
        self.assertFalse(self.requests)

    def test_original_html_static_and_downloads_keep_the_prefix(self):
        self.login()
        response = self.client.get("/auth-bridge", follow_redirects=False)
        self.assertEqual(response.headers["location"], "/auth-bridge/")
        source = '<html><head><link href="/app.css"><script type="module" src="/app.js"></script></head><body></body></html>'
        self.answer = lambda req: httpx.Response(200, text=source, headers={"content-type": "text/html", "X-Frame-Options": "DENY"})
        response = self.client.get("/auth-bridge/")
        self.assertIn('href="/auth-bridge/app.css"', response.text)
        self.assertIn('src="/auth-bridge/app.js"', response.text)
        self.assertLess(response.text.index('bridge-embedded.js'), response.text.index('/auth-bridge/app.js'))
        self.assertIn('href="/static/css/bridge-embedded.css"', response.text)
        self.assertEqual(response.headers["x-frame-options"], "SAMEORIGIN")
        self.private(response)
        self.answer = lambda req: httpx.Response(200, content=b"fixture-session", headers={
            "Content-Type": "text/plain; charset=utf-8", "Content-Disposition": 'attachment; filename="sessions.txt"'})
        response = self.client.post("/auth-bridge/api/v2/accounts/export-sessions", json={"ids": [1]})
        self.assertEqual(response.content, b"fixture-session")
        self.assertIn('filename="sessions.txt"', response.headers["content-disposition"])
        self.assertTrue(all(client.is_closed for client in self.clients))

    def test_native_json_and_sse_preserve_methods_metadata_and_private_headers(self):
        self.login()
        chunks = [b'event: progress\ndata: {"stage":"import"}\n\n', b'event: complete\ndata: {"ok":true}\n\n']
        stream = TrackedStream(chunks)
        self.answer = lambda req: httpx.Response(200, stream=stream, headers={
            "Content-Type": "text/event-stream", "X-Request-Id": "request-1", "X-Operation-Id": "operation-1"})
        response = self.client.post("/auth-bridge/api/v2/accounts/reset-totp?after=2", json={"ids": [1, 2], "concurrency": 2},
            headers={"accept": "text/event-stream", "origin": "http://testserver", "x-request-id": "request-1", "last-event-id": "2",
                     "authorization": "private-team48-auth"})
        self.assertEqual(response.content, b"".join(chunks))
        self.private(response)
        self.assertEqual(response.headers["x-accel-buffering"], "no")
        request = self.requests[-1]
        self.assertEqual(str(request.url), "http://127.0.0.1:4174/api/v2/accounts/reset-totp?after=2")
        self.assertEqual(json.loads(request.content), {"ids": [1, 2], "concurrency": 2})
        self.assertEqual(request.headers["last-event-id"], "2")
        for header in ("cookie", "authorization", "origin"):
            self.assertNotIn(header, request.headers)
        self.assertTrue(stream.closed)
        self.assertTrue(self.clients[-1].is_closed)
        self.answer = lambda req: httpx.Response(200, json={"ok": True})
        for method in ("PUT", "PATCH", "DELETE"):
            self.assertEqual(self.client.request(method, "/auth-bridge/api/v2/jobs/fixture", json={}).status_code, 200)
            self.assertEqual(self.requests[-1].method, method)

    def test_path_origin_input_boundaries_and_error_redaction(self):
        self.login()
        for path in ("/auth-bridge/%252e%252e/.env", "/auth-bridge/api//accounts", "/auth-bridge/http:%2F%2Fevil.test", "/auth-bridge/%5Cetc"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 400, path)
            self.private(response)
        for headers in ({"origin": "http://elsewhere.test"}, {"sec-fetch-site": "same-site"}, {"sec-fetch-site": "cross-site"}):
            response = self.client.post("/auth-bridge/api/v2/accounts/import", json={}, headers=headers)
            self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.post("/auth-bridge/app.js", json={}).status_code, 405)
        self.assertEqual(self.client.post("/auth-bridge/api/v2/accounts/import", content="raw").status_code, 415)
        with patch("app.web.routes.bridge_embed.MAX_BODY_BYTES", 16):
            response = self.client.post("/auth-bridge/api/v2/accounts/import", json={"text": "private-secret"})
            self.assertEqual(response.status_code, 413)
            self.assertNotIn("private-secret", response.text)
        self.assertFalse(self.requests)
        self.answer = lambda req: httpx.Response(429, json={"code": "TASK_QUEUE_FULL", "error": "private-upstream-secret"}, headers={"Retry-After": "2"})
        response = self.client.post("/auth-bridge/api/v2/accounts/import", json={})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.json()["code"], "TASK_QUEUE_FULL")
        self.assertNotIn("private-upstream-secret", response.text)
        self.assertEqual(response.headers["retry-after"], "2")
        self.private(response)

    def test_redirect_and_transport_errors_never_leave_loopback(self):
        self.login()
        self.answer = lambda req: httpx.Response(302, headers={"location": "https://example.test/?token=private"})
        response = self.client.get("/auth-bridge/")
        self.assertEqual(response.status_code, 502)
        self.assertNotIn("private", response.text)
        self.answer = lambda req: httpx.Response(302, headers={"location": "/index.html"})
        response = self.client.get("/auth-bridge/", follow_redirects=False)
        self.assertEqual(response.headers["location"], "/auth-bridge/index.html")

        def unavailable(req):
            raise httpx.ConnectError("private-upstream-secret")
        self.answer = unavailable
        response = self.client.get("/auth-bridge/")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("private-upstream-secret", response.text)
        self.assertTrue(all(client.is_closed for client in self.clients))
        self.assertTrue(_safe_path("api/v2/accounts/export-sessions"))
        for bad in ("../api", "//host/api", "api//accounts", "api%2faccounts", "http://host", "api\\x"):
            self.assertFalse(_safe_path(bad))
        for origin in ("http://localhost:4174", "https://127.0.0.1:4174", "http://127.0.0.1:4174/path", "http://u:p@127.0.0.1:4174", "http://127.0.0.1:4174/?x=1"):
            with self.assertRaises(Exception):
                _upstream(SimpleNamespace(auth_bridge_url=origin))


class DisconnectTests(unittest.IsolatedAsyncioTestCase):
    async def test_downstream_cancellation_closes_stream_and_client(self):
        first_chunk_sent = anyio.Event()

        class SlowStream(TrackedStream):
            async def __aiter__(self):
                yield b'data: {"type":"progress"}\n\n'
                await anyio.sleep(30)

        stream = SlowStream([])
        upstream_client = httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200,
            stream=stream, headers={"Content-Type": "text/event-stream"})))
        app = app_fixture()
        endpoint = next(route.endpoint for route in build_bridge_embed_router().routes
                        if route.path == "/auth-bridge/{path:path}")
        scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "method": "POST",
                 "path": "/auth-bridge/api/model-evaluation", "raw_path": b"/auth-bridge/api/model-evaluation",
                 "query_string": b"", "headers": [(b"content-type", b"application/json")],
                 "scheme": "http", "server": ("testserver", 80), "client": ("127.0.0.1", 1), "app": app}
        body_read = False

        async def receive():
            nonlocal body_read
            if not body_read:
                body_read = True
                return {"type": "http.request", "body": b"{}", "more_body": False}
            await first_chunk_sent.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            if message["type"] == "http.response.body" and message.get("body"):
                first_chunk_sent.set()

        with patch("app.web.routes.bridge_embed._new_bridge_client", return_value=upstream_client):
            response = await endpoint(Request(scope, receive), "api/model-evaluation")
            with anyio.fail_after(3):
                await response(scope, receive, send)
        self.assertTrue(stream.closed)
        self.assertTrue(upstream_client.is_closed)


if __name__ == "__main__":
    unittest.main()
