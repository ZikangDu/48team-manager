"""Exercise the native workbench in Chromium with synthetic HTTP responses only."""
import json
import os
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

from tests.helpers import make_client


def main():
    with tempfile.TemporaryDirectory() as tmp, make_client(Path(tmp), _env_file=None) as client, sync_playwright() as pw:
        assert client.post("/auth/login", json={"username": "hixz12", "password": "test-password"}).is_success
        browser = pw.chromium.launch(channel=os.getenv("TEAM48_CHROMIUM_CHANNEL"))
        for width, theme in [(1280, "light"), (390, "dark")]:
            context = browser.new_context(viewport={"width": width, "height": 850}, reduced_motion="reduce")
            page = context.new_page()
            errors = []
            calls = []
            page.on("pageerror", lambda error: errors.append(str(error)))

            def intercept(route):
                req = route.request
                url = urlsplit(req.url)
                if url.hostname == "api.example.test":
                    assert url.path == "/v1/responses" and req.method in {"POST", "OPTIONS"}
                    cors = {"access-control-allow-origin": "*", "access-control-allow-headers": "*"}
                    if req.method == "OPTIONS":
                        return route.fulfill(status=204, headers=cors)
                    assert req.headers.get("authorization") == "Bearer demo-api-key"
                    calls.append("provider")
                    return route.fulfill(json={"status": "completed", "output_text": "答案：21"}, headers=cors)
                if url.hostname != "testserver":
                    errors.append("Unexpected request outside test app")
                    return route.abort()
                if url.path == "/api/bridge-workbench/accounts":
                    return route.fulfill(json={"ok": True, "accounts": [
                        {"id": 7, "email": "member@example.org", "plan": "team", "has_access_token": True, "proxy_compatible": True},
                        {"id": 9, "email": "other@example.org", "plan": "free", "has_access_token": False, "proxy_compatible": False},
                    ]})
                if url.path.startswith("/api/bridge-workbench/accounts/7/"):
                    action = url.path.split("/")[-1]
                    calls.append(action)
                    if action == "health":
                        assert req.post_data_json == {}
                        return route.fulfill(json={"ok": True, "healthy": True, "status": 200, "message": "会话可用。",
                            "quota": {"five_hour_used_percent": 0, "seven_day_used_percent": 30}})
                    if action == "workspaces":
                        return route.fulfill(json={"workspaces": [{"id": 3, "name": "示例工作区", "role": "member", "state": "joined"}]})
                    assert action == "evaluation"
                    data = req.post_data_json
                    assert set(data) == {"question", "model", "reasoning_effort"}
                    html = "<html><body><svg xmlns='http://www.w3.org/2000/svg'></svg></body></html>"
                    events = [{"type": "phase", "phase": "waiting"}, {"type": "delta", "delta": "<html>"},
                              {"type": "complete", "status": "manual_review", "output": html, "durationMs": 100}]
                    return route.fulfill(content_type="text/event-stream", body="".join("data: " + json.dumps(x) + "\n\n" for x in events))
                assert req.method == "GET", url.path
                resp = client.get(url.path + ("?" + url.query if url.query else ""))
                headers = {k: v for k, v in resp.headers.items() if k not in {"content-length", "content-encoding"}}
                return route.fulfill(status=resp.status_code, body=resp.content, headers=headers)

            page.route("**/*", intercept)
            page.goto("http://testserver/tools/auth-bridge?tool=model-evaluation")
            page.get_by_label("外观模式").select_option(theme)
            expect(page.locator("#bridge-account")).to_be_enabled()
            expect(page.locator("#evaluation-start")).to_be_disabled()
            page.get_by_label("当前账号", exact=True).select_option("7")
            page.get_by_label("测试题").select_option("pelican")
            page.get_by_role("button", name="开始评测").click()
            expect(page.locator("#evaluation-status")).to_contain_text("请预览核对")
            page.get_by_role("button", name="预览动画").click()
            expect(page.locator("#evaluation-preview")).to_be_visible()
            page.get_by_role("link", name="工作区", exact=True).click()
            expect(page.locator("#workspace-list a")).to_have_attribute("href", "/accounts?view=teams&workspace=3")
            page.get_by_role("link", name="会话测活").click()
            page.get_by_role("button", name="检查会话").click()
            expect(page.locator("#health-five")).to_have_text("0%")
            page.get_by_label("当前账号", exact=True).select_option("9")
            expect(page.locator("#health-details")).to_be_hidden()
            expect(page.locator("#bridge-check")).to_be_disabled()
            expect(page.locator("#bridge-account-detail")).to_have_attribute("href", "/accounts?account=9")
            page.get_by_role("link", name="模型评测").click()
            page.get_by_label("评测来源").select_option("api")
            page.get_by_label("API 地址").fill("https://api.example.test/v1")
            page.get_by_label("API Key", exact=True).fill("demo-api-key")
            page.get_by_label("测试题").select_option("candy")
            page.get_by_role("button", name="开始评测").click()
            expect(page.locator("#evaluation-status")).to_have_text("答案正确")
            expect(page.get_by_label("API Key", exact=True)).to_have_value("")
            assert calls == ["evaluation", "workspaces", "health", "provider"]
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            if folder := os.getenv("TEAM48_SCREENSHOTS"):
                page.screenshot(path=Path(folder) / f"workbench-{width}.png", full_page=True)
            assert not errors, errors
            context.close()
        browser.close()
    print("Workbench browser scenarios passed at 1280px and 390px")


if __name__ == "__main__":
    main()
