"""Browser-free transport for the MFA client, over a logged-in ChatGPT web session.

A protocol login (via the local Bridge) yields a web-session access token and the
cookies behind it. This transport replays the account-security requests the same
way a signed-in browser would — TLS impersonation through curl_cffi, the session
cookies, the account's fixed proxy — so app/application/totp_reset.py can run its
durable 2FA reset with no visible browser. Only (status, text) leaves it; nothing
is logged.
"""
from __future__ import annotations

import asyncio
import json
import re
import uuid

from app.integrations.openai.mfa import ChatGPTMfaClient, MfaTransportError

CHATGPT_ORIGIN = "https://chatgpt.com"
_COOKIE_HOSTS = ("chatgpt.com", "openai.com")
_IMPERSONATE = "chrome"


def _cookies_from_storage(storage_state_json: str) -> tuple[dict, str]:
    """Return (cookie jar for chatgpt.com, oai-device-id) from a Playwright storage state."""
    try:
        state = json.loads(storage_state_json or "{}")
    except (ValueError, TypeError):
        return {}, ""
    jar: dict[str, str] = {}
    for cookie in state.get("cookies", []) if isinstance(state, dict) else ():
        if not isinstance(cookie, dict):
            continue
        domain = str(cookie.get("domain") or "").lstrip(".").lower()
        name, value = cookie.get("name"), cookie.get("value")
        if isinstance(name, str) and isinstance(value, str) and any(domain == host or domain.endswith("." + host) for host in _COOKIE_HOSTS):
            jar[name] = value
    device = jar.get("oai-device-id") or jar.get("oai-did") or ""
    device = device if re.fullmatch(r"[A-Za-z0-9._-]{8,80}", device) else ""
    return jar, device


class HttpSessionTransport:
    """Same-origin chatgpt.com requests over curl_cffi with the session's cookies."""

    def __init__(self, *, storage_state_json: str, proxy: str = "", locale: str = "en-US"):
        self._cookies, self._device = _cookies_from_storage(storage_state_json)
        self._proxies = {"http": proxy, "https": proxy} if proxy else None
        self._locale = locale or "en-US"
        self._session_id = str(uuid.uuid4())

    @property
    def has_cookies(self) -> bool:
        return bool(self._cookies)

    async def request(self, method: str, path: str, *, headers: dict, body: str | None):
        """Return (status, text). Any failure to obtain a response is MfaTransportError."""
        if (method not in {"GET", "POST"} or not isinstance(path, str)
                or not re.fullmatch(r"/[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*", path)):
            raise MfaTransportError()
        sent = {**headers, "oai-session-id": self._session_id, "oai-language": self._locale,
                "origin": CHATGPT_ORIGIN, "referer": CHATGPT_ORIGIN + "/"}
        if self._device:
            sent["oai-device-id"] = self._device
        try:
            status, text = await asyncio.to_thread(self._send, method, CHATGPT_ORIGIN + path, sent, body)
        except Exception:
            raise MfaTransportError() from None
        finally:
            sent.clear()
        if not isinstance(status, int) or isinstance(status, bool):
            raise MfaTransportError()
        return status, text if isinstance(text, str) else None

    def _send(self, method: str, url: str, headers: dict, body: str | None):
        from curl_cffi import requests as curl_requests
        response = curl_requests.request(
            method, url, headers=headers, data=body.encode("utf-8") if body is not None else None,
            cookies=self._cookies, impersonate=_IMPERSONATE, proxies=self._proxies,
            allow_redirects=False, timeout=45,
        )
        text = response.text
        return response.status_code, text if len(text) <= 262144 else None

    def close(self) -> None:
        self._cookies = {}
        self._device = ""


def protocol_mfa_client(*, expected_email: str, storage_state_json: str, proxy: str = "",
                        locale: str = "en-US") -> ChatGPTMfaClient:
    """An MFA client bound to one email, talking over a protocol web session."""
    return ChatGPTMfaClient(HttpSessionTransport(storage_state_json=storage_state_json, proxy=proxy, locale=locale),
                            expected_email=expected_email)
