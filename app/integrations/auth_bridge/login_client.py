"""Loopback-only client for the local GPTAuthBridge protocol-login service.

The Bridge logs ChatGPT accounts in by protocol (email + password + TOTP, no
browser) and can do many at once. Team48 calls it over 127.0.0.1 only, passes
each account's credentials inline for one request, and keeps only the machine
codes and the returned credentials — never the Bridge's raw error strings, which
may quote secrets. Request shapes follow gpt-auth-bridge (MIT; see
docs/third-party/gpt-auth-bridge-LICENSE.txt).
"""
from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import urlsplit

import httpx

HEALTH_PATH = "/api/health"
CONFIG_PATH = "/api/system/config"
LOGIN_PATH = "/api/v2/accounts/protocol-login-pipeline"
ALLOWED_PATHS = frozenset((HEALTH_PATH, CONFIG_PATH, LOGIN_PATH))
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
# Bridge budget per account is 90 s queue + 900 s work; allow the batch to breathe.
LOGIN_TIMEOUT_SECONDS = 1100
MAX_BATCH = 50
_CRED_LIMIT = 65536


class BridgeError(ValueError):
    def __init__(self, code: str, message: str, status_code: int = 400):
        super().__init__(message)
        self.code, self.message, self.status_code = code, message, status_code


def normalize_bridge_url(value: str) -> str:
    """A loopback http origin with a port, nothing else — never a forwarding proxy."""
    raw = str(value or "").strip()
    try:
        if not raw or any(ord(char) < 33 or ord(char) == 127 for char in raw):
            raise ValueError
        parsed = urlsplit(raw)
        if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
                or parsed.port is None or not 1 <= parsed.port <= 65535
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                or "?" in raw or "#" in raw):
            raise ValueError
        host = "[::1]" if parsed.hostname == "::1" else "127.0.0.1"
        return f"http://{host}:{parsed.port}"
    except (TypeError, ValueError):
        raise BridgeError("bridge_url_invalid", "授权桥地址必须是带端口的本机 HTTP 地址") from None


def _text(value: Any, *, limit: int = _CRED_LIMIT) -> str:
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > limit:
        raise BridgeError("bridge_response_invalid", "授权桥返回的数据格式不兼容", 502)
    return value


def _failure_code(row: dict, payload: dict) -> str:
    """One machine code for a failed account; upstream strings are never surfaced."""
    codes: list[str] = []
    for source in (row, payload):
        if isinstance(source, dict):
            codes.extend(str(source.get(key) or "") for key in ("code", "error_code", "terminalReason"))
            failure = source.get("validationFailure")
            if isinstance(failure, dict):
                codes.append(str(failure.get("code") or ""))
    joined = {code for code in codes if code}
    if "EMAIL_VERIFICATION_REQUIRED" in joined:
        return "bridge_email_verification"
    if joined & {"ACCOUNT_DEACTIVATED", "account_unavailable"}:
        return "bridge_account_unavailable"
    if joined & {"INVALID_PASSWORD", "INVALID_TOTP", "invalid_credentials", "LOGIN_CREDENTIALS_MISSING"}:
        return "bridge_credentials_rejected"
    if any(code.startswith("VALIDATION_") for code in joined):
        return "bridge_validation_failed"
    return "bridge_login_failed"


def _clean_account(row: dict, *, expected_id: str, expected_email: str) -> dict:
    """Keep only the credential fields; drop password, TOTP, cookies and diagnostics."""
    if (not isinstance(row, dict) or str(row.get("id") or "") != expected_id
            or str(row.get("email") or "").strip().lower() != expected_email):
        raise BridgeError("bridge_identity_mismatch", "授权桥返回了其他账号的数据，未保存凭据", 502)
    account: dict[str, Any] = {"email": expected_email}
    for name in ("openai_rt", "openai_access_token", "openai_id_token", "openai_account_id"):
        account[name] = _text(row.get(name))
    workspaces = row.get("business_workspace_credentials") or []
    if not isinstance(workspaces, list) or len(workspaces) > 100:
        raise BridgeError("bridge_response_invalid", "授权桥返回的数据格式不兼容", 502)
    credentials = []
    for item in workspaces:
        if not isinstance(item, dict):
            raise BridgeError("bridge_response_invalid", "授权桥返回的数据格式不兼容", 502)
        credential = {key: _text(item.get(key)) for key in ("workspaceId", "accessToken", "refreshToken", "idToken", "accountId")}
        if credential["accessToken"]:
            credentials.append(credential)
    account["business_workspace_credentials"] = credentials
    return account


class BridgeLoginClient:
    def __init__(self, base_url: str, *, transport: httpx.AsyncBaseTransport | None = None):
        self.base_url = normalize_bridge_url(base_url)
        self._transport = transport

    async def _request(self, path: str, *, body: dict | None = None, timeout: float = 5) -> dict:
        if path not in ALLOWED_PATHS:
            raise BridgeError("bridge_path_invalid", "不支持此授权桥操作")
        try:
            async with asyncio.timeout(timeout):
                async with httpx.AsyncClient(base_url=self.base_url, trust_env=False, follow_redirects=False,
                                             timeout=httpx.Timeout(timeout, connect=5), transport=self._transport) as client:
                    response = await client.request("POST" if body is not None else "GET", path,
                                                    json=body, headers={"Accept": "application/json"})
                    if 300 <= response.status_code < 400:
                        raise BridgeError("bridge_redirect_refused", "授权桥地址发生重定向，已停止发送凭据", 502)
                    if response.status_code == 429:
                        raise BridgeError("bridge_busy", "授权桥繁忙，请稍后重试", 503)
                    if response.status_code >= 400:
                        raise BridgeError("bridge_request_failed", "授权桥拒绝了请求，请检查本机服务", 502)
                    raw = response.content
                    if len(raw) > MAX_RESPONSE_BYTES:
                        raise BridgeError("bridge_response_too_large", "授权桥响应过大，已停止读取", 502)
                    try:
                        payload = json.loads(raw)
                    except (ValueError, UnicodeError, RecursionError):
                        raise BridgeError("bridge_response_invalid", "授权桥返回的数据格式不兼容", 502) from None
                    if not isinstance(payload, dict):
                        raise BridgeError("bridge_response_invalid", "授权桥返回的数据格式不兼容", 502)
                    return payload
        except (asyncio.TimeoutError, httpx.TimeoutException):
            raise BridgeError("bridge_timeout", "授权桥请求超时；未重放登录，请核对后重试", 504) from None
        except httpx.HTTPError:
            raise BridgeError("bridge_unavailable", "无法连接本机授权桥，请先启动 GPTAuthBridge", 503) from None

    async def status(self) -> dict:
        health = await self._request(HEALTH_PATH)
        config = await self._request(CONFIG_PATH)
        concurrency = config.get("taskConcurrency")
        if (health.get("ok") is not True or health.get("service") != "email-server"
                or config.get("ok") is not True or type(concurrency) is not int or not 1 <= concurrency <= 30):
            raise BridgeError("bridge_incompatible", "本机服务不是兼容版本的 GPTAuthBridge", 502)
        reset_version = config.get("totpResetProtocolVersion")
        return {"ok": True, "available": True, "base_url": self.base_url, "task_concurrency": concurrency,
                "totp_reset_version": reset_version if type(reset_version) is int else None,
                "message": "授权桥已连接；支持邮箱、密码和 2FA 密钥协议登录"}

    async def _pipeline(self, accounts: list[dict], *, workspace_mode: str, proxy: str, concurrency: int) -> dict:
        if not accounts:
            raise BridgeError("bridge_no_accounts", "没有要登录的账号")
        if len(accounts) > MAX_BATCH:
            raise BridgeError("bridge_batch_too_large", f"单次最多 {MAX_BATCH} 个账号")
        body = {"ids": [item["id"] for item in accounts], "workspaceMode": workspace_mode,
                "requireNonPersonal": False, "stream": False, "concurrency": int(concurrency),
                # An explicit empty pool means direct. Bridge's legacy "direct"
                # mode actually uses its default OPENAI_PROXY_URL when set.
                "proxyMode": "pool", "proxyPool": proxy,
                "browserState": {"accounts": [dict(item) for item in accounts]}}
        try:
            return await self._request(LOGIN_PATH, body=body, timeout=LOGIN_TIMEOUT_SECONDS)
        finally:
            for item in body["browserState"]["accounts"]:
                item.clear()
            body.clear()

    async def login_batch(self, accounts: list[dict], *, proxy: str = "", concurrency: int = 5,
                          workspace_mode: str = "all") -> list[dict]:
        """Log in several accounts; one row per account with its importable credentials.

        ``accounts`` items: {id, email, openai_password, two_factor_secret}. The
        returned ``account`` dict (when ok) is shaped for credential_import.
        """
        by_id = {item["id"]: str(item["email"]).strip().lower() for item in accounts}
        payload = await self._pipeline(accounts, workspace_mode=workspace_mode, proxy=proxy, concurrency=concurrency)
        rows = (payload.get("browserState") or {}).get("accounts")
        results = payload.get("results")
        rows = {str(row.get("id")): row for row in rows if isinstance(row, dict)} if isinstance(rows, list) else {}
        results = {str(item.get("id")): item for item in results if isinstance(item, dict)} if isinstance(results, list) else {}
        outcome = []
        for identity, email in by_id.items():
            result = results.get(identity) or {}
            ok = result.get("ok") is True
            entry = {"id": identity, "email": email, "ok": ok, "code": "ok" if ok else _failure_code(result, payload),
                     "account": None}
            if ok:
                try:
                    cleaned = _clean_account(rows.get(identity) or {}, expected_id=identity, expected_email=email)
                    if not cleaned["openai_access_token"] and not cleaned["business_workspace_credentials"]:
                        entry.update(ok=False, code=_failure_code(result, payload))
                    else:
                        entry["account"] = cleaned
                except BridgeError as exc:
                    entry.update(ok=False, code=exc.code)
            outcome.append(entry)
        payload.clear()
        return outcome

    async def login_web_session(self, *, email: str, password: str, totp_secret: str, proxy: str = "",
                                attempts: int = 2, pause: float = 20.0) -> dict:
        """One account's ChatGPT web session (token + cookies) for an MFA operation.

        Logging in only reads; repeat logins of one account in quick succession are
        intermittently refused upstream, so a failed attempt is retried after a pause.
        Rejected credentials or an unavailable account are never retried.
        """
        final = {"bridge_credentials_rejected", "bridge_account_unavailable", "bridge_email_verification",
                 "bridge_identity_mismatch", "bridge_unavailable", "bridge_incompatible"}
        for attempt in range(1, max(1, attempts) + 1):
            try:
                return await self._login_web_session_once(email=email, password=password,
                                                          totp_secret=totp_secret, proxy=proxy)
            except BridgeError as exc:
                if exc.code in final or attempt >= attempts:
                    raise
                await asyncio.sleep(pause)
        raise BridgeError("bridge_login_failed", "协议登录未取得会话", 502)

    async def _login_web_session_once(self, *, email: str, password: str, totp_secret: str, proxy: str = "") -> dict:
        identity = "team48-session"
        account = {"id": identity, "email": str(email).strip().lower(),
                   "openai_password": password, "two_factor_secret": totp_secret}
        payload = await self._pipeline([account], workspace_mode="session", proxy=proxy, concurrency=1)
        try:
            rows = (payload.get("browserState") or {}).get("accounts")
            row = rows[0] if isinstance(rows, list) and rows else {}
            result = (payload.get("results") or [{}])
            result = result[0] if isinstance(result, list) and result else {}
            if result.get("ok") is not True:
                raise BridgeError(_failure_code(result, payload), "协议登录未取得会话，请核对密码和 2FA 密钥", 502)
            if (str(row.get("id") or "") != identity
                    or str(row.get("email") or "").strip().lower() != account["email"]):
                raise BridgeError("bridge_identity_mismatch", "授权桥返回了其他账号的会话", 502)
            token = _text(row.get("session_access_token"))
            storage = _text(row.get("storage_state_json"), limit=3 * 1024 * 1024)
            if not token or not storage:
                raise BridgeError("bridge_session_missing", "协议登录未返回可用会话", 502)
            return {"email": account["email"], "session_access_token": token, "storage_state_json": storage}
        finally:
            payload.clear()
