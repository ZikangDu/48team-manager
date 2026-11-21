"""Exercise the complete embedded Bridge with synthetic HTTP and browser state only."""
from __future__ import annotations

import copy
import json
import mimetypes
import os
import tempfile
from pathlib import Path
from urllib.parse import urlsplit
from unittest.mock import patch

from playwright.sync_api import expect, sync_playwright

from app.web.routes.bridge_embed import _embed_html
from tests.helpers import make_client
from tests.test_credential_import import WS, token

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "vendor/auth-bridge/docs"
MODULES = Path(os.getenv("TEAM48_BRIDGE_NODE_MODULES", ROOT / "vendor/auth-bridge/node_modules"))
OLD_KEY = "JBSWY3DPEHPK3PXP"
NEW_KEY = "GEZDGNBVGY3TQOJQ"
BASE = "http://localhost:43219"
EMAILS = [f"embedded-{index}@example.test" for index in range(3)]


def stream(events):
    return "".join("event: " + name + "\ndata: " + json.dumps(data) + "\n\n" for name, data in events)


def main():
    with patch("app.application.jobs.scheduler.start_scheduler"), patch("app.application.jobs.scheduler.stop_scheduler"), \
            tempfile.TemporaryDirectory() as temp, make_client(Path(temp), _env_file=None) as client, sync_playwright() as pw:
        assert client.post("/auth/login", json={"username": "hixz12", "password": "test-password"}).is_success
        browser = pw.chromium.launch(channel=os.getenv("TEAM48_CHROMIUM_CHANNEL", "chrome"), headless=True)
        context = browser.new_context(viewport={"width": 1280, "height": 900}, reduced_motion="reduce")
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        calls = []
        reset_actions = []
        saved_backups = []
        auto_saved = []
        records = []
        activation_attempted = False
        validation_blocked = False

        def account(index):
            email = EMAILS[index]
            access = token(email=email)
            return {"id": str(index + 1), "email": email, "openai_password": "fixture-password",
                    "two_factor_secret": OLD_KEY, "status": "已导入", "session_access_token": access,
                    "session_json": json.dumps({"accessToken": access, "sessionToken": "fixture-session",
                        "user": {"email": email, "id": "fixture-user"}, "account": {"id": WS, "planType": "team"}}),
                    "business_workspace_credentials": [{"workspaceId": WS, "accountId": WS, "accessToken": access,
                        "refreshToken": "fixture-refresh", "status": "active"}]}

        def intercept(route):
            nonlocal records, activation_attempted
            request = route.request
            url = urlsplit(request.url)
            assert url.hostname == "localhost", "Unexpected external browser request"
            path = url.path
            if path.startswith("/auth-bridge/"):
                relative = path.removeprefix("/auth-bridge/")
                if not relative:
                    return route.fulfill(content_type="text/html", body=_embed_html((DOCS / "index.html").read_text()))
                if not relative.startswith("api/"):
                    if relative == "vendor/markdown-it.min.js":
                        source = MODULES / "markdown-it/dist/markdown-it.min.js"
                    else:
                        source = DOCS / relative
                    assert source.is_file(), relative
                    return route.fulfill(content_type=mimetypes.guess_type(source.name)[0] or "application/octet-stream", body=source.read_bytes())
                if relative == "api/system/config":
                    return route.fulfill(json={"taskConcurrency": 3, "totpResetProtocolVersion": 2})
                calls.append(relative)
                body = request.post_data_json
                op = {"schemaVersion": "1.0.0", "operationId": body.get("operationId")}
                if relative == "api/v2/accounts/import":
                    records = [account(i) for i in range(3)]
                    return route.fulfill(json={"ok": True, **op, "rows": [{"id": row["id"], "email": row["email"]} for row in records],
                        "browserState": {"accounts": records, "settings": {}}})
                if relative == "api/v2/accounts/protocol-login-pipeline":
                    assert body["concurrency"] == 3 and body["workspaceMode"] == "all" and body["requireNonPersonal"] is True
                    assert body["proxyMode"] == "pool" and len(body["proxyPool"].splitlines()) == 3
                    results = [{"id": row["id"], "email": row["email"], "ok": True, "sessionOk": True,
                        "personalOk": False, "businessSuccess": 1} for row in records]
                    if validation_blocked:
                        for result in results:
                            result.update(ok=False, sessionOk=False, businessSuccess=0,
                                validationFailure={"code": "VALIDATION_CONFIG_MISSING", "stage": "sentinel"})
                    events = [("account_start", {**op, "id": row["id"], "email": row["email"]}) for row in records]
                    events += [("browser_state", {**op, "accounts": records, "settings": {}})]
                    events += [("account_done", {**op, **result}) for result in results]
                    events += [("summary", {**op, "ok": True, "concurrency": 3,
                        "success": 0 if validation_blocked else 3, "failed": 3 if validation_blocked else 0,
                        "accounts": records, "results": results})]
                    return route.fulfill(content_type="text/event-stream", body=stream(events))
                if relative == "api/v2/accounts/export-sessions":
                    assert body["ids"] == ["1", "2", "3"] and body["download"] is True
                    return route.fulfill(content_type="text/plain", body="fixture-session-1\nfixture-session-2\nfixture-session-3")
                if relative == "api/v2/accounts/reset-totp":
                    action = body["action"]
                    reset_actions.append(action)
                    assert body["concurrency"] == 3 and len(body["ids"]) == 3
                    records = copy.deepcopy(body["browserState"]["accounts"])
                    if action == "prepare":
                        for row in records:
                            row["totp_reset_pending"] = {"phase": "prepared", "secret": NEW_KEY}
                    elif action == "activate":
                        assert not activation_attempted
                        activation_attempted = True
                        # The candidate must be durably saved before the activation request.
                        saved = page.frame(url=BASE + "/auth-bridge/").evaluate("async () => (await browserWorkspace.read()).state.browserAccounts")
                        assert all(row["totp_reset_pending"] == {"phase": "activating", "secret": NEW_KEY} for row in saved)
                        for row in records:
                            row["two_factor_secret"] = NEW_KEY
                            row["totp_reset_pending"]["phase"] = "activated"
                    elif action == "confirm":
                        assert activation_attempted
                        assert all(row["totp_reset_pending"]["phase"] == "activated" for row in records)
                        for row in records:
                            row["two_factor_secret"] = NEW_KEY
                            row["totp_reset_pending"] = None
                            row["status"] = "已换绑2FA"
                    else:
                        raise AssertionError(action)
                    phase = {"prepare": "prepared", "activate": "activated", "confirm": "confirmed"}[action]
                    results = [{"id": row["id"], "email": row["email"], "ok": action != "activate", "phase": phase} for row in records]
                    events = [("account_start", {**op, "id": row["id"], "email": row["email"]}) for row in records]
                    events += [("browser_state", {**op, "accounts": records, "settings": {}})]
                    events += [("account_done", {**op, **result}) for result in results]
                    events += [("summary", {**op, "ok": True, "results": results, "success": 0 if action == "activate" else 3,
                        "failed": 3 if action == "activate" else 0})]
                    return route.fulfill(content_type="text/event-stream", body=stream(events))
                if relative == "api/session-health":
                    return route.fulfill(json={"ok": True, "results": [{"index": i, "status": 200, "deviceCount": 2,
                        "devicesStatus": 200, "devices": [], "firstLoginAt": 1700000000000, "lastLoginAt": 1700100000000,
                        "usage": {"fiveHour": {"usedPercent": 10}, "sevenDay": {"usedPercent": 20}}}
                        for i, _ in enumerate(body["accounts"])]})
                raise AssertionError("Unexpected Bridge operation " + relative)
            if path == "/api/bridge-workbench/accounts":
                return route.fulfill(json={"ok": True, "accounts": [{"id": 7, "email": EMAILS[0], "plan": "team", "has_access_token": True}]})
            if path == "/api/bridge-workbench/accounts/export":
                assert request.post_data_json == {"account_ids": [7], "confirm": True}
                return route.fulfill(json={"ok": True, "accounts": [{"email": EMAILS[0], "accessToken": token(email=EMAILS[0]),
                    "user": {"email": EMAILS[0], "id": "fixture-user"}, "account": {"id": WS, "planType": "team"}}]})
            if path == "/api/bridge-workbench/authorizations/auto-save":
                credentials = request.post_data_json["accounts"]
                assert "fixture-password" not in json.dumps(credentials)
                assert OLD_KEY not in json.dumps(credentials)
                auto_saved.extend(row["email"] for row in credentials)
                return route.fulfill(json={"ok": True, "saved": 1, "blocked": 0,
                    "results": [{"email": row["email"], "status": "saved", "account_id": EMAILS.index(row["email"]) + 10,
                        "followup": {"operation_id": "fixture-check", "queued": True}} for row in credentials]})
            if path.startswith("/api/bridge-workbench/authorizations/") and path.endswith("/status"):
                return route.fulfill(json={"ok": True, "done": True, "role": "owner", "quota": "ready", "sync": "success",
                    "message": "已识别母号；额度刷新完成；成员同步完成"})
            if path == "/api/credential-import/preview":
                assert request.post_data_json["content"]["accounts"]
                return route.fulfill(json={"ok": True, "draft_id": "fixture-draft", "candidates": [{"id": "fixture-candidate",
                    "email": EMAILS[0], "workspace_id": WS, "plan": "team", "allowed": True}]})
            if path == "/api/credential-import/commit":
                assert request.post_data_json["selected_ids"] == ["fixture-candidate"]
                return route.fulfill(json={"ok": True, "imported": [{"email": EMAILS[0]}]})
            if path == "/api/assisted-login/totp-backup":
                assert request.post_data_json["secret"] == NEW_KEY and request.post_data_json["confirmed"] is True
                saved_backups.append(request.post_data_json["email"])
                return route.fulfill(json={"ok": True})
            assert request.method == "GET", "Unexpected parent mutation " + path
            response = client.get(path + ("?" + url.query if url.query else ""))
            headers = {key: value for key, value in response.headers.items() if key not in {"content-length", "content-encoding"}}
            return route.fulfill(status=response.status_code, headers=headers, body=response.content)

        page.route("**/*", intercept)
        page.goto(BASE + "/tools/auth-bridge")
        expect(page.locator("#bridge-kernel-status")).to_have_text("内嵌授权内核已连接")
        bridge = page.frame_locator("#bridge-frame")
        expect(bridge.locator("#login-workbench")).to_be_visible()
        for tool in ["sub2api", "model-evaluation", "sub2api-tools", "team-checkout", "protocol-login"]:
            button = bridge.locator('.top-nav [data-format="' + tool + '"]')
            button.click()
            expect(button).to_have_attribute("aria-pressed", "true")
        expect(bridge.locator('input[name="login-proxy-mode"][value="direct"]')).to_be_checked()
        bridge.locator('input[name="login-proxy-mode"][value="local"]').check()
        expect(bridge.locator("#login-proxy-local-port")).to_be_visible()
        bridge.locator("#login-proxy-local-port").fill("7899")
        bridge.locator('input[name="login-proxy-mode"][value="pool"]').check()
        pool = "proxy.example:10000:fixture-user:fixture-password\nfixture-user:fixture-password@proxy.example:10001\nsocks5://fixture-user:fixture-password@proxy.example:10002"
        bridge.locator("#login-proxy-pool").fill(pool)
        bridge.locator('input[name="login-workspace-mode"][value="session"]').check()
        bridge.locator('input[name="login-workspace-mode"][value="all"]').check()
        bridge.locator("#login-require-non-personal").check()
        bridge.locator("#login-accounts").fill("\n".join(email + "----fixture-password----" + OLD_KEY for email in EMAILS))
        bridge.locator("#start-protocol-login").click()
        expect(bridge.locator("#login-status")).to_contain_text("全部流程完成：成功 3")
        expect(page.locator("#bridge-auto-save-status")).to_contain_text("本页已保存 3 个账号")
        expect(page.locator("#bridge-auto-save-status")).to_contain_text("额度刷新完成")
        if os.getenv("TEAM48_SCREENSHOTS"):
            for width, theme in [(1280, "light"), (390, "dark")]:
                page.set_viewport_size({"width": width, "height": 900})
                page.get_by_label("外观模式").select_option(theme)
                page.evaluate("window.scrollTo(0, 0)")
                page.screenshot(path=str(Path(os.environ["TEAM48_SCREENSHOTS"]) / f"followup-success-{width}-{theme}.png"))
            page.set_viewport_size({"width": 1280, "height": 900})
        assert sorted(set(auto_saved)) == sorted(EMAILS)
        expect(bridge.get_by_role("link", name="打开账号与团队")).to_have_count(0)
        expect(bridge.locator("#export-login-sessions")).to_be_enabled()
        expect(bridge.locator("#export-login-business")).to_be_enabled()
        expect(bridge.locator("#export-login-personal")).to_be_disabled()
        with page.expect_download() as exported:
            bridge.locator("#export-login-sessions").click()
        assert exported.value.suggested_filename.startswith("chatgpt-sessions.")
        page.on("dialog", lambda dialog: dialog.accept())
        bridge.locator("#reset-login-totp").click()
        expect(bridge.locator("#login-reset-pending")).to_be_visible()
        expect(bridge.locator("#login-status")).to_contain_text("待处理 3")
        assert reset_actions == ["prepare", "activate"]
        page.reload()
        expect(page.locator("#bridge-kernel-status")).to_have_text("内嵌授权内核已连接")
        bridge = page.frame_locator("#bridge-frame")
        expect(bridge.locator("#login-reset-pending")).to_be_visible()
        bridge.locator("#resume-login-totp").click()
        expect(bridge.locator("#login-status")).to_contain_text("成功 3，失败 0，待处理 0")
        assert reset_actions == ["prepare", "activate", "confirm"]
        expect(bridge.locator("#login-reset-output")).to_be_visible()
        expect(bridge.locator("#login-reset-pending")).to_be_hidden()
        page.locator("#bridge-import").click()
        page.locator('#bridge-exchange-items input[data-kind="account"]').check()
        page.locator("#bridge-exchange-confirm").check()
        page.locator("#bridge-exchange-submit").click()
        expect(page.locator("#bridge-feedback")).to_contain_text("已将所选账号的授权导入工作台")
        page.locator("#bridge-save").click()
        expect(page.locator('#bridge-exchange-items input[data-kind="credential"]')).to_be_visible()
        expect(page.locator('#bridge-exchange-items input[data-kind="backup"]')).to_have_count(3)
        for checkbox in page.locator('#bridge-exchange-items input[data-kind="backup"]').all():
            checkbox.check()
        page.locator("#bridge-exchange-confirm").check()
        page.locator("#bridge-exchange-submit").click()
        expect(page.locator("#bridge-exchange")).not_to_be_visible()
        assert sorted(saved_backups) == sorted(EMAILS)
        expect(page.locator("#bridge-feedback")).to_contain_text("已保存 1 个账号")
        validation_blocked = True
        bridge.locator("#start-protocol-login").click()
        expect(bridge.locator(".login-account-stage", has_text="需要人工验证")).to_have_count(3)
        action = bridge.get_by_role("link", name="打开账号与团队").first
        expect(action).to_be_visible()
        expect(action).to_have_attribute("href", "/accounts?view=all")
        expect(bridge.locator(".login-account-log").first).to_contain_text("请在官方登录页面手动完成授权")
        for width, theme in [(1280, "light"), (390, "dark")]:
            page.set_viewport_size({"width": width, "height": 900})
            page.get_by_label("外观模式").select_option(theme)
            expect(bridge.locator("html")).to_have_attribute("data-theme", theme)
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            assert page.frame(url=BASE + "/auth-bridge/").evaluate("document.documentElement.scrollWidth <= innerWidth")
            screenshot_dir = os.getenv("TEAM48_SCREENSHOTS")
            if screenshot_dir:
                page.screenshot(path=str(Path(screenshot_dir) / f"workbench-{width}-{theme}.png"), full_page=False)
        assert not errors, errors
        assert all(path.startswith("api/") for path in calls)
        context.close()
        browser.close()
    print("Full embedded Bridge tabs, proxy/workspace options, 3-account durable 2FA recovery and parent exchange passed offline")


if __name__ == "__main__":
    main()
