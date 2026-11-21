"""Recoverable mixed automatic-save outcomes, without real account credentials."""
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

from tests.helpers import make_client


def main():
    with patch("app.application.jobs.scheduler.start_scheduler"), patch("app.application.jobs.scheduler.stop_scheduler"), \
            tempfile.TemporaryDirectory() as tmp, make_client(Path(tmp), _env_file=None) as client, sync_playwright() as pw:
        client.post("/auth/login", json={"username": "hixz12", "password": "test-password"})
        browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
        for width, theme in [(1280, "light"), (390, "dark")]:
            page = browser.new_page(viewport={"width": width, "height": 900})
            calls = []

            def intercept(route):
                req = route.request
                url = urlsplit(req.url)
                assert url.hostname == "testserver"
                if url.path == "/auth-bridge/":
                    return route.fulfill(content_type="text/html", body='<div id="format-toolbar">模拟授权工作台</div>')
                if url.path == "/api/bridge-workbench/authorizations/auto-save":
                    email = req.post_data_json["accounts"][0]["email"]
                    calls.append(email)
                    if len(calls) == 1:
                        return route.fulfill(status=401, json={"detail": "unauthenticated"})
                    return route.fulfill(json={"ok": True, "saved": 1, "blocked": 0,
                        "results": [{"email": email, "status": "saved"}]})
                response = client.get(url.path + ("?" + url.query if url.query else ""))
                route.fulfill(status=response.status_code, body=response.content,
                    headers={k: v for k, v in response.headers.items() if k not in {"content-length", "content-encoding"}})

            page.route("**/*", intercept)
            page.goto("http://testserver/tools/auth-bridge")
            page.get_by_label("外观模式").select_option(theme)
            frame = page.frame(url="http://testserver/auth-bridge/")
            frame.evaluate("parent.postMessage({channel:'team48-auth-bridge',type:'ready'},location.origin)")
            expect(page.locator("#bridge-kernel-status")).to_have_text("内嵌授权内核已连接")

            def announce(email):
                frame.evaluate("email => parent.postMessage({channel:'team48-auth-bridge',type:'authorization-complete',accounts:[{email,access_token:'synthetic-not-a-token'}]},location.origin)", email)

            announce("first@example.test")
            status = page.locator("#bridge-auto-save-status")
            expect(status).to_contain_text("后台登录已过期，请重新登录")
            announce("second@example.test")
            expect(status).to_contain_text("本页已保存 1 个账号")
            expect(status).to_contain_text("另有 1 批授权尚未保存")
            expect(status).to_have_attribute("data-tone", "danger")
            if os.getenv("TEAM48_SCREENSHOTS"):
                page.screenshot(path=str(Path(os.environ["TEAM48_SCREENSHOTS"]) / f"auto-save-pending-{width}-{theme}.png"))
            page.locator("#bridge-auto-save-retry").click()
            expect(status).to_contain_text("本页已保存 2 个账号")
            expect(status).not_to_contain_text("尚未保存")
            expect(status).to_have_attribute("data-tone", "")
            expect(page.locator("#bridge-auto-save-retry")).to_be_hidden()
            assert calls == ["first@example.test", "second@example.test", "first@example.test"]
            page.locator("#bridge-auto-save").uncheck()
            announce("disabled@example.test")
            page.wait_for_timeout(100)
            assert len(calls) == 3
            page.close()
        browser.close()
    print("Expired login, mixed success/pending saves, explicit retry and opt-out passed")


if __name__ == "__main__":
    main()
