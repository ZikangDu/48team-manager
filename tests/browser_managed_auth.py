"""Proxy controls and batch payloads in a real browser, with synthetic HTTP only."""
import os
import tempfile
from pathlib import Path
from urllib.parse import urlsplit
from unittest.mock import patch

from playwright.sync_api import expect, sync_playwright

from tests.helpers import make_client


def main():
    with patch("app.application.jobs.scheduler.start_scheduler"), patch("app.application.jobs.scheduler.stop_scheduler"), \
            tempfile.TemporaryDirectory() as tmp, make_client(Path(tmp), _env_file=None) as client, sync_playwright() as pw:
        client.post("/auth/login", json={"username": "hixz12", "password": "test-password"})
        browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
        for width, theme in [(1280, "light"), (390, "dark")]:
            page = browser.new_page(viewport={"width": width, "height": 900}, reduced_motion="reduce")
            calls, errors = [], []
            page.on("pageerror", lambda error: errors.append(str(error)))

            def intercept(route):
                req = route.request
                url = urlsplit(req.url)
                assert url.hostname == "testserver"
                if url.path == "/api/protocol-auth/capabilities":
                    return route.fulfill(json={"ok": True, "available": True})
                if url.path == "/api/resources/proxies":
                    return route.fulfill(json={"items": [], "configured": False})
                if url.path == "/api/protocol-auth/options":
                    return route.fulfill(json={"ok": True, "default_has_proxy": False,
                        "workspaces": [{"id": 42, "name": "测试母号团队", "owner_email": "owner@example.test"}],
                        "proxies": [{"id": 7, "name": "测试代理档案"}]})
                if url.path == "/api/protocol-auth/batch-login":
                    calls.append(req.post_data_json)
                    return route.fulfill(status=202, json={"ok": True, "operation_id": "fixture-operation", "status": "running"})
                if url.path == "/api/protocol-auth/fixture-operation":
                    return route.fulfill(json={"ok": True, "state": "success", "op_type": "protocol_login",
                        "result": {"imported": 0, "total": 1, "results": [{"email": "child@example.test", "login": "failed",
                            "code": "owner_proxy_missing", "message": "团队母号未绑定可用代理，请先配置母号代理。"}]}})
                response = client.request(req.method, url.path + ("?" + url.query if url.query else ""))
                return route.fulfill(status=response.status_code, body=response.content,
                    headers={k: v for k, v in response.headers.items() if k not in {"content-length", "content-encoding"}})

            page.route("**/*", intercept)
            page.goto("http://testserver/accounts")
            page.get_by_label("外观模式").select_option(theme)
            page.get_by_role("button", name="登记账号或团队").click()
            page.get_by_role("menuitem", name="登记团队", exact=True).click()
            expect(page.locator("#register-protocol-import")).to_be_visible()
            output = os.getenv("TEAM48_SCREENSHOTS")
            if output:
                page.screenshot(path=str(Path(output) / f"register-protocol-{width}-{theme}.png"))
            page.locator("#register-protocol-import").click()
            expect(page.locator('[data-assist-mode="protocol"]')).to_have_attribute("aria-selected", "true")
            start = page.get_by_role("button", name="开始批量登录", exact=True)
            expect(start).to_be_enabled()
            mode = page.locator('[name="protocol_proxy_mode"]')
            expect(mode).to_have_value("auto")
            mode.select_option("inherit")
            team = page.locator('[name="protocol_workspace_id"]')
            expect(team.locator("option")).to_have_count(2)
            team.select_option("42")
            page.locator('[name="protocol_concurrency"]').fill("2")
            text = page.locator('[name="protocol_accounts"]')
            text.fill("child@example.test----fixture-password----JBSWY3DPEHPK3PXP")
            output = os.getenv("TEAM48_SCREENSHOTS")
            if output:
                page.screenshot(path=str(Path(output) / f"batch-proxy-{width}-{theme}.png"))
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            before = len(calls)
            page.locator('[name="protocol_concurrency"]').fill("")
            start.click()
            assert len(calls) == before
            assert not page.locator('[name="protocol_concurrency"]').evaluate("element => element.checkValidity()")
            page.locator('[name="protocol_concurrency"]').fill("2")
            start.click()
            expect(page.locator(".protocol-account-list")).to_contain_text("团队母号未绑定可用代理")
            assert calls[-1]["proxy_mode"] == "inherit" and calls[-1]["workspace_id"] == 42
            assert calls[-1]["concurrency"] == 2 and "proxy" not in calls[-1]
            for value in ["custom", "profile", "direct"]:
                mode.select_option(value)
                if value == "custom":
                    page.locator('[name="protocol_proxy_url"]').fill("socks5://proxy-user:proxy-secret@proxy.test:1080")
                if value == "profile":
                    page.locator('[name="protocol_proxy_profile_id"]').select_option("7")
                text.fill("child@example.test----fixture-password")
                start.click()
                expect(text).to_have_value("")
                expect(start).to_be_enabled()
                assert calls[-1]["proxy_mode"] == value
                assert calls[-1]["workspace_id"] == 42
                if value == "custom":
                    assert calls[-1]["proxy"] == "socks5://proxy-user:proxy-secret@proxy.test:1080"
                if value == "profile":
                    assert calls[-1]["proxy_profile_id"] == 7 and "proxy" not in calls[-1]
            assert not errors, errors
            page.close()
        browser.close()
    print("Batch proxy modes, inherited team, concurrency, failures and desktop/mobile layouts passed")


if __name__ == "__main__":
    main()
