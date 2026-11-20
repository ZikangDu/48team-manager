"""ChatGPT account MFA (TOTP) calls behind an injected, already signed-in transport.

Request shapes follow the account-security flow of gpt-auth-bridge (MIT, see
docs/third-party/gpt-auth-bridge-LICENSE.txt). Nothing here opens a connection:
the transport performs same-origin requests inside the signed-in chatgpt.com
page. Tokens, keys and response bodies never enter exceptions, logs or return
values, except the enrolment that is handed to the caller for encrypted storage.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import struct
import time
from dataclasses import dataclass

from app.core.jwt import jwt_parser

SESSION_PATH = "/api/auth/session"
MFA_INFO_PATH = "/backend-api/accounts/mfa_info"
MFA_ENROLL_PATH = "/backend-api/accounts/mfa/enroll"
MFA_DISABLE_PATH = "/backend-api/accounts/mfa/user/disable_in_house"
MFA_ACTIVATE_PATH = "/backend-api/accounts/mfa/user/activate_enrollment"
TOTP_PERIOD = 30
_REMOTE_CODE = re.compile(r"[A-Za-z0-9_]{1,80}")


class MfaTransportError(Exception):
    """No response was obtained, so whether the server acted is unknown."""


class MfaError(Exception):
    """A failed call; the message is a fixed code and never carries remote text.

    ``outcome`` is "rejected" when the server answered without applying the
    request and "unknown" when the request may have been applied.
    """

    def __init__(self, code: str, *, outcome: str, status: int = 0, remote_code: str = ""):
        super().__init__(code)
        self.code, self.outcome, self.status, self.remote_code = code, outcome, status, remote_code

    @property
    def rejected(self) -> bool:
        return self.outcome == "rejected"


@dataclass(frozen=True)
class MfaState:
    enabled: bool
    totp_factor_ids: tuple[str, ...] = ()
    default_factor_id: str = ""

    @property
    def active_factor_id(self) -> str:
        return self.totp_factor_ids[0] if self.totp_factor_ids else self.default_factor_id


@dataclass(frozen=True, repr=False)
class Enrollment:
    secret: str
    session_id: str
    factor_id: str


def normalize_totp_secret(value) -> str:
    """Canonical Base32 key (no spaces, hyphens or padding); ValueError when unusable."""
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError("Invalid authenticator key")
    secret = re.sub(r"[\s-]", "", value).upper().rstrip("=")
    if not 16 <= len(secret) <= 128 or not re.fullmatch("[A-Z2-7]+", secret):
        raise ValueError("Invalid authenticator key")
    try:
        if len(base64.b32decode(secret + "=" * (-len(secret) % 8))) < 10:
            raise ValueError("Invalid authenticator key")
    except (ValueError, base64.binascii.Error):
        raise ValueError("Invalid authenticator key") from None
    return secret


def generate_totp(secret: str, *, timestamp: float | None = None) -> str:
    """RFC 6238 SHA-1, six digits, 30-second period; never logs input/output."""
    if not isinstance(secret, str):
        raise ValueError("Invalid authenticator key")
    normalized = re.sub(r"[\s-]", "", secret).upper().rstrip("=")
    if not 16 <= len(normalized) <= 256 or not re.fullmatch("[A-Z2-7]+", normalized):
        raise ValueError("Invalid authenticator key")
    try:
        key = base64.b32decode(normalized + "=" * (-len(normalized) % 8))
    except (ValueError, base64.binascii.Error):
        raise ValueError("Invalid authenticator key") from None
    stamp = time.time() if timestamp is None else timestamp
    if not isinstance(stamp, (int, float)) or isinstance(stamp, bool) or not math.isfinite(stamp) or stamp < 0:
        raise ValueError("Invalid authenticator time")
    digest = hmac.new(key, struct.pack(">Q", int(stamp // TOTP_PERIOD)), hashlib.sha1).digest()
    offset = digest[-1] & 15
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{number % 1000000:06d}"


def totp_seconds_left(timestamp: float | None = None) -> float:
    """Seconds until the current TOTP code rolls over."""
    stamp = time.time() if timestamp is None else timestamp
    return TOTP_PERIOD - (stamp % TOTP_PERIOD)


def _identifier(value) -> str:
    """Opaque id as the reference reads it (String(value).trim()): text or a whole number, no blanks."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return ""
    text = str(value).strip()
    return text if 0 < len(text) <= 4096 and not any(ord(char) < 33 or ord(char) == 127 for char in text) else ""


def _truthy(value) -> bool:
    """JavaScript truthiness, as the reference tests `payload?.error` and `mfa_enabled`."""
    if value is None or value is False:
        return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value == value and value != 0
    if isinstance(value, str):
        return value != ""
    return True  # objects and arrays are truthy even when empty


def _decode(text) -> dict | None:
    """A JSON object, or None for anything else (an empty body is not an answer)."""
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        payload = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return payload if isinstance(payload, dict) else None


def _remote_code(payload) -> str:
    if not isinstance(payload, dict):
        return ""
    error, detail = payload.get("error"), payload.get("detail")
    for candidate in (error.get("code") if isinstance(error, dict) else None,
                      detail.get("code") if isinstance(detail, dict) else None, payload.get("code")):
        if isinstance(candidate, str) and _REMOTE_CODE.fullmatch(candidate):
            return candidate
    return ""


class ChatGPTMfaClient:
    """One signed-in web session, bound to exactly one expected email."""

    def __init__(self, transport, *, expected_email: str):
        self._transport = transport
        self._expected = str(expected_email or "").strip().lower()
        self._token = ""

    def close(self) -> None:
        self._token = ""

    async def open_session(self) -> None:
        """Read the page's own web session; refuse any identity but the expected one."""
        # An empty 2xx body means "no session" (rejected); a non-object/garbage body is unreadable (unknown).
        payload = await self._call("session", "GET", SESSION_PATH, bearer=False, allow_empty=True)
        token = payload.get("accessToken") or payload.get("access_token")
        if not isinstance(token, str) or not token or len(token) > 16384 or any(ord(char) < 33 for char in token):
            raise MfaError("session_missing", outcome="rejected")
        user = payload.get("user")
        claims = jwt_parser.decode_token(token) or {}
        profile = claims.get("https://api.openai.com/profile")
        emails = (user.get("email") if isinstance(user, dict) else None, claims.get("email"),
                  profile.get("email") if isinstance(profile, dict) else None)
        seen = [item.strip().lower() for item in emails if isinstance(item, str) and item.strip()]
        if not self._expected or not seen or any(item != self._expected for item in seen):
            raise MfaError("session_identity_mismatch", outcome="rejected")
        self._token = token

    async def state(self) -> MfaState:
        payload = await self._call("info", "GET", MFA_INFO_PATH)
        if not any(name in payload for name in ("mfa_enabled", "mfa_enabled_v2", "factors")):
            # An unrecognised shape must never be read as "2FA is off".
            raise MfaError("info_invalid_response", outcome="unknown")
        factors = payload.get("factors")
        totp = factors.get("totp") if isinstance(factors, dict) else None
        ids: list[str] = []
        listed = totp if isinstance(totp, list) else []
        for factor in listed:
            factor_id = _identifier(factor.get("id")) if isinstance(factor, dict) else ""
            if factor_id and factor_id not in ids:
                ids.append(factor_id)
        if listed and not ids:
            # Factors are listed but none can be named: never read that as "nothing to disable".
            raise MfaError("info_invalid_response", outcome="unknown")
        return MfaState(enabled=_truthy(payload.get("mfa_enabled")) or _truthy(payload.get("mfa_enabled_v2")),
                        totp_factor_ids=tuple(ids),
                        default_factor_id=_identifier(payload.get("native_default_factor_id")))

    async def disable(self, factor_id: str) -> None:
        if not _identifier(factor_id):
            raise MfaError("disable_rejected", outcome="rejected")
        await self._call("disable", "POST", MFA_DISABLE_PATH, body={"factor_id": factor_id})

    async def enroll(self) -> Enrollment:
        payload = await self._call("enroll", "POST", MFA_ENROLL_PATH, body={"factor_type": "totp"})
        session_id = _identifier(payload.get("session_id"))
        factor = payload.get("factor")
        try:
            secret = normalize_totp_secret(payload.get("secret"))
            if not session_id:
                raise ValueError("Missing enrolment session")
        except ValueError:
            # The enrolment may exist remotely, but nothing usable was returned.
            raise MfaError("enroll_invalid_response", outcome="unknown") from None
        return Enrollment(secret, session_id, _identifier(factor.get("id")) if isinstance(factor, dict) else "")

    async def activate(self, *, code: str, session_id: str) -> None:
        await self._call("activate", "POST", MFA_ACTIVATE_PATH,
                         body={"code": code, "factor_type": "totp", "session_id": session_id})

    async def _call(self, label: str, method: str, path: str, *, body: dict | None = None, bearer: bool = True, allow_empty: bool = False) -> dict:
        if bearer and not self._token:
            raise MfaError("session_missing", outcome="rejected")
        headers = {"accept": "*/*" if bearer else "application/json"}
        if bearer:
            headers.update({"authorization": "Bearer " + self._token,
                            "x-openai-target-path": path, "x-openai-target-route": path})
        raw = None
        if body is not None:
            raw = json.dumps(body, separators=(",", ":"))
            headers["content-type"] = "application/json"
        try:
            status, text = await self._transport.request(method, path, headers=headers, body=raw)
        except MfaTransportError:
            raise MfaError(label + "_no_response", outcome="unknown") from None
        finally:
            headers.clear()
        payload = _decode(text)
        if not isinstance(status, int) or isinstance(status, bool):
            raise MfaError(label + "_no_response", outcome="unknown")
        remote = _remote_code(payload)
        if 200 <= status <= 299:
            empty = text is not None and not text.strip()
            if payload is None and empty and (allow_empty or (status == 204 and label in ("disable", "activate"))):
                return {}  # an empty body: a usable acknowledgement here (no session for session reads)
            if payload is None:
                raise MfaError(label + "_invalid_response", outcome="unknown", status=status)
            if _truthy(payload.get("error")) or payload.get("success") is False:
                raise MfaError(label + "_rejected", outcome="rejected", status=status, remote_code=remote)
            return payload
        if status == 401:
            raise MfaError("session_rejected", outcome="rejected", status=status, remote_code=remote)
        if status == 429:
            raise MfaError("rate_limited", outcome="rejected", status=status, remote_code=remote)
        if 500 <= status <= 599:
            # The server may have applied a change before failing to answer.
            raise MfaError(label + "_server_error", outcome="unknown", status=status, remote_code=remote)
        # Redirects (reported as 0), 4xx and edge challenges were answered without applying anything.
        raise MfaError(label + "_rejected", outcome="rejected", status=status, remote_code=remote)
