"""Pure, bounded credential-file parsing. JWT claims are not live verification.

Input formats are interoperability contracts, not an instruction to import every
field. Passwords, TOTP, cookies, remote IDs and provider settings are discarded.
"""
from __future__ import annotations

import json
import math
import re
import time
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import jwt

from app.domain.automation import DEFAULT_OAUTH_CLIENT_ID

MAX_CONTENT_BYTES = 5 * 1024 * 1024
MAX_CANDIDATES = 50
MAX_TOKEN_LENGTH = 65536
AUTH = "https://api.openai.com/auth"
PROFILE = "https://api.openai.com/profile"


class CredentialImportError(ValueError):
    def __init__(self, code: str, message: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def _error(code: str, message: str) -> CredentialImportError:
    return CredentialImportError(code, message)


def normalize_email(value: Any) -> str:
    if not isinstance(value, str):
        raise _error("email_missing", "授权记录缺少有效邮箱")
    value = value.strip().lower()
    if len(value) > 255 or not re.fullmatch(r'[^\s@<>;,"\x00-\x1f]+@[^\s@<>;,"\x00-\x1f]+\.[^\s@<>;,"\x00-\x1f]+', value):
        raise _error("email_invalid", "授权记录的邮箱格式不正确")
    return value


def _uuid(value: Any) -> str:
    if not isinstance(value, str):
        raise _error("workspace_missing", "访问令牌缺少官方工作区 UUID")
    try:
        parsed = UUID(value.strip())
    except (ValueError, AttributeError):
        raise _error("workspace_invalid", "授权记录的工作区标识不是有效 UUID") from None
    if parsed.int == 0:
        raise _error("workspace_invalid", "授权记录的工作区标识不是有效 UUID")
    return str(parsed)


def _text(value: Any, *, limit: int = MAX_TOKEN_LENGTH) -> str:
    if value is None or value == "":
        return ""
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 for c in value):
        raise _error("field_invalid", "授权记录包含无效或过长的字段")
    return value.strip()


def _values(sources: list[dict], names: tuple[str, ...]) -> list[Any]:
    return [source[name] for source in sources for name in names if name in source and source[name] not in (None, "")]


def _consistent(values: list[Any], normalizer, code: str, message: str) -> str:
    normalized = [normalizer(value) for value in values]
    if len(set(normalized)) > 1:
        raise _error(code, message)
    return normalized[0] if normalized else ""


def _jwt(value: str, *, kind: str) -> dict:
    try:
        header = jwt.get_unverified_header(value)
        if not header.get("alg") or str(header["alg"]).lower() == "none":
            raise ValueError()
        result = jwt.decode(value, options={"verify_signature": False, "verify_exp": False, "verify_aud": False})
        if not isinstance(result, dict):
            raise ValueError()
        return result
    except Exception:
        raise _error("invalid_token", f"{kind} 格式无效；无法解析身份") from None


def _obj(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _load_json(value: str):
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = item
        return result

    def constant(_value):
        raise ValueError("non-finite number")

    return json.loads(value, object_pairs_hook=pairs, parse_constant=constant)


def _normalize(record: dict, format_name: str, *, now: float) -> dict:
    creds = _obj(record.get("credentials"))
    tokens = _obj(record.get("tokens"))
    meta = _obj(record.get("meta"))
    extra = _obj(record.get("extra"))
    provider = _obj(record.get("providerSpecificData"))
    sources = [record, creds, tokens, provider]
    if record.get("platform") not in (None, "", "openai") or record.get("provider") not in (None, "", "openai", "codex"):
        raise _error("provider_unsupported", "仅支持 OpenAI 授权凭据")
    if creds.get("auth_mode") or record.get("agent_private_key") or creds.get("agent_private_key"):
        raise _error("auth_mode_unsupported", "暂不支持 Agent Identity 私钥凭据，请导出 OAuth 凭据")
    access = _consistent(_values(sources, ("access_token", "accessToken")), _text,
                         "token_conflict", "记录中存在不一致的访问令牌")
    if not access:
        raise _error("access_token_missing", "记录缺少访问令牌；只有密码、Cookie 或刷新令牌不能导入")
    claims = _jwt(access, kind="访问令牌")
    auth, profile = _obj(claims.get(AUTH)), _obj(claims.get(PROFILE))
    claim_email = _consistent(_values([profile, claims], ("email",)), normalize_email,
                              "email_mismatch", "访问令牌中的邮箱信息不一致")
    if not claim_email:
        raise _error("identity_missing", "访问令牌没有可识别的邮箱，不能仅相信文件标签")
    claim_workspace = _consistent(_values([auth], ("chatgpt_account_id", "account_id")), _uuid,
                                  "workspace_mismatch", "访问令牌中的工作区信息不一致")
    claim_user = _consistent(_values([auth], ("chatgpt_user_id", "user_id")),
                             lambda value: _text(value, limit=100), "user_mismatch", "访问令牌中的用户信息不一致")
    claim_client = _consistent(_values([claims], ("client_id", "azp")),
                               lambda value: _text(value, limit=100), "client_mismatch", "访问令牌中的客户端信息不一致")
    if not claim_workspace or not claim_user or not claim_client:
        raise _error("identity_missing", "访问令牌缺少工作区、用户或客户端身份")
    if any(c.isspace() for c in claim_user + claim_client):
        raise _error("identity_invalid", "访问令牌的用户或客户端身份格式无效")
    exp = claims.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)) or not math.isfinite(exp):
        raise _error("expiry_missing", "访问令牌缺少有效的到期时间")
    if exp <= now:
        raise _error("access_token_expired", "访问令牌已过期，请在认证工作台更新后重新导入")
    try:
        expires_at = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()
    except (OverflowError, ValueError, OSError):
        raise _error("expiry_invalid", "访问令牌的到期时间无效") from None

    explicit_email = _consistent(_values(sources + [_obj(record.get("user")), extra, meta], ("email", "chatgpt_email")),
                                 normalize_email, "email_mismatch", "文件中的邮箱与令牌身份不一致")
    explicit_workspace = _consistent(_values(sources + [extra, meta, _obj(record.get("account"))],
                                              ("workspace_id", "workspaceId", "chatgpt_account_id", "chatgptAccountId", "account_id", "accountId"))
                                     + _values([_obj(record.get("account"))], ("id",)),
                                     _uuid, "workspace_mismatch", "文件中的工作区标识不一致")
    explicit_user = _consistent(_values(sources, ("chatgpt_user_id", "chatgptUserId", "user_id"))
                                + _values([_obj(record.get("user"))], ("id",)),
                                lambda value: _text(value, limit=100), "user_mismatch", "文件中的用户标识不一致")
    explicit_client = _consistent(_values(sources, ("client_id", "clientId")),
                                  lambda value: _text(value, limit=100), "client_mismatch", "文件中的客户端标识不一致")
    for supplied, actual, code, message in (
        (explicit_email, claim_email, "email_mismatch", "文件邮箱与访问令牌不一致"),
        (explicit_workspace, claim_workspace, "workspace_mismatch", "文件工作区与访问令牌不一致"),
        (explicit_user, claim_user, "user_mismatch", "文件用户与访问令牌不一致"),
        (explicit_client, claim_client, "client_mismatch", "文件客户端与访问令牌不一致"),
    ):
        if supplied and supplied != actual:
            raise _error(code, message)

    refresh = _consistent(_values(sources, ("refresh_token", "refreshToken")), _text,
                          "token_conflict", "记录中存在不一致的刷新令牌")
    session = _consistent(_values(sources, ("session_token", "sessionToken")), _text,
                          "token_conflict", "记录中存在不一致的 Session token")
    warnings = ["仅解析了凭据身份，尚未向官方验证可用性"]
    if refresh and claim_client != DEFAULT_OAUTH_CLIENT_ID:
        raise _error("refresh_client_unsupported", "带刷新令牌的导入仅支持 Codex OAuth 客户端")
    if not refresh:
        warnings.append("没有刷新令牌，到期后需要手动重新授权；更新时不会保留旧刷新令牌")
    synthetic = any(source.get("id_token_synthetic") is True for source in sources + [extra])
    identity_token = "" if synthetic else _consistent(_values(sources, ("id_token", "idToken")), _text,
                                                     "token_conflict", "记录中存在不一致的身份令牌")
    if synthetic:
        warnings.append("已忽略格式转换器生成的合成 ID token")
    if identity_token:
        identity = _jwt(identity_token, kind="ID token")
        iauth, iprofile = _obj(identity.get(AUTH)), _obj(identity.get(PROFILE))
        comparisons = (
            (_values([identity, iprofile], ("email",)), normalize_email, claim_email),
            (_values([iauth], ("chatgpt_account_id", "account_id")), _uuid, claim_workspace),
            (_values([iauth], ("chatgpt_user_id", "user_id")), lambda value: _text(value, limit=100), claim_user),
            (_values([identity], ("client_id", "azp")), lambda value: _text(value, limit=100), claim_client),
        )
        for values, normalize, expected in comparisons:
            if any(normalize(value) != expected for value in values):
                raise _error("id_token_mismatch", "ID token 与访问令牌身份不一致")
        aud = identity.get("aud")
        if aud is not None and (not isinstance(aud, (str, list)) or claim_client not in ([aud] if isinstance(aud, str) else aud)):
            raise _error("id_token_mismatch", "ID token 的受众与访问令牌客户端不一致")
    workspace_name = record.get("workspace_name") or record.get("workspaceName") or ""
    workspace_name = workspace_name.strip() if isinstance(workspace_name, str) else ""
    if len(workspace_name) > 120 or any(ord(c) < 32 for c in workspace_name) or workspace_name in {access, refresh, identity_token, session}:
        workspace_name = ""
    return {
        "email": claim_email, "workspace_id": claim_workspace, "user_id": claim_user,
        "client_id": claim_client, "workspace_name": workspace_name, "format": format_name,
        "access_token": access, "refresh_token": refresh, "id_token": identity_token,
        "session_token": session, "expires_at": expires_at, "expires_timestamp": exp,
        "plan": str(auth.get("chatgpt_plan_type") or "unknown"), "warnings": warnings,
    }


def parse_credentials(content: str | dict | list, *, now: float | None = None) -> tuple[list[dict], list[dict]]:
    """Return normalized secrets internally and fixed-message errors separately."""
    try:
        if isinstance(content, str):
            if len(content.encode("utf-8")) > MAX_CONTENT_BYTES:
                raise _error("content_too_large", "导入内容不能超过 5 MiB")
            root = _load_json(content)
        elif isinstance(content, (dict, list)):
            encoded = json.dumps(content, ensure_ascii=False, allow_nan=False)
            if len(encoded.encode("utf-8")) > MAX_CONTENT_BYTES:
                raise _error("content_too_large", "导入内容不能超过 5 MiB")
            root = content
        else:
            raise _error("invalid_json", "请提供 JSON 对象或数组")
    except CredentialImportError:
        raise
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise _error("invalid_json", "JSON 格式无效，或结构过深") from None
    records: list[tuple[dict, str]] = []
    errors: list[dict] = []
    visited = 0

    def add(value: dict, kind: str) -> None:
        if len(records) >= MAX_CANDIDATES:
            raise _error("too_many_candidates", "单次最多解析 50 组工作区凭据")
        records.append((value, kind))

    def walk(value: Any, depth: int = 0) -> None:
        nonlocal visited
        visited += 1
        if depth > 12 or visited > 500:
            raise _error("structure_too_complex", "导入结构过深或记录过多")
        if isinstance(value, list):
            for item in value:
                walk(item, depth + 1)
            return
        if not isinstance(value, dict):
            errors.append({"code": "record_invalid", "message": "列表中的记录必须是 JSON 对象"})
            return
        if isinstance(value.get("browserState"), dict):
            walk(value["browserState"], depth + 1)
            return
        state = _obj(value.get("state"))
        if isinstance(state.get("browserAccounts"), list):
            walk(state["browserAccounts"], depth + 1)
            return
        if isinstance(value.get("browserAccounts"), list):
            walk(value["browserAccounts"], depth + 1)
            return
        if isinstance(value.get("accounts"), list):
            walk(value["accounts"], depth + 1)
            return
        if isinstance(value.get("tokens"), dict) or isinstance(value.get("credentials"), dict):
            add(value, "sub2api" if "credentials" in value else "token-json")
            return
        bridge_fields = ("openai_access_token", "business_workspace_credentials", "business_openai_access_token", "session_access_token", "session_json")
        if any(key in value for key in bridge_fields):
            initial = len(records)
            email = value.get("email")
            if value.get("openai_access_token"):
                add({"email": email, "access_token": value.get("openai_access_token"), "refresh_token": value.get("openai_rt"),
                     "id_token": value.get("openai_id_token"), "account_id": value.get("openai_account_id")}, "bridge-personal")
            else:
                session = value.get("session_json")
                if isinstance(session, str) and session.strip():
                    try:
                        session = _load_json(session)
                    except (ValueError, TypeError, RecursionError):
                        errors.append({"code": "session_json_invalid", "message": "Bridge Session JSON 格式无效"})
                        session = {}
                session = dict(_obj(session))
                # Check redundant fields before adding canonical aliases. Otherwise
                # an outer AT can silently replace the AT paired with an inner RT.
                token = _consistent(
                    _values([{"access_token": value.get("session_access_token")}, session],
                            ("accessToken", "access_token")),
                    _text, "token_conflict", "Bridge Session 中存在不一致的访问令牌")
                session_email = _consistent(
                    _values([{"email": email}, session, _obj(session.get("user"))],
                            ("email", "chatgpt_email")),
                    normalize_email, "email_mismatch", "Bridge Session 的内外邮箱不一致")
                if token:
                    session.update(email=session_email, accessToken=token)
                    add(session, "bridge-session")
            workspaces = {}
            if value.get("business_openai_access_token"):
                key = value.get("business_workspace_id") or value.get("business_openai_account_id") or ""
                workspaces[_uuid(key) if key else ""] = {"workspaceId": key, "accessToken": value.get("business_openai_access_token"),
                                        "refreshToken": value.get("business_openai_rt"), "idToken": value.get("business_openai_id_token"),
                                        "accountId": value.get("business_openai_account_id")}
            entries = value.get("business_workspace_credentials", [])
            if not isinstance(entries, list):
                errors.append({"code": "record_invalid", "message": "Bridge 工作区凭据必须为数组"})
                entries = []
            entry_ids = set()
            for item in entries:
                if not isinstance(item, dict):
                    errors.append({"code": "record_invalid", "message": "Bridge 工作区凭据记录无效"})
                    continue
                entry_id = item.get("workspaceId") or item.get("workspace_id") or ""
                entry_key = _uuid(entry_id) if entry_id else ""
                if entry_key in entry_ids:
                    raise _error("duplicate_workspace", "Bridge 账号包含重复工作区记录，请先整理授权数据")
                entry_ids.add(entry_key)
                legacy = workspaces.get(entry_key)
                # A confirmed departure excludes even stale legacy credentials.
                # For retained workspaces, validate both copies before replacing
                # the legacy bundle; never combine fields from conflicting copies.
                if legacy is not None and item.get("status") != "left":
                    sources = [legacy, item, _obj(item.get("credentials")),
                               _obj(item.get("tokens")), _obj(item.get("providerSpecificData"))]
                    for aliases in (("access_token", "accessToken"),
                                    ("refresh_token", "refreshToken"),
                                    ("id_token", "idToken"),
                                    ("session_token", "sessionToken")):
                        _consistent(_values(sources, aliases), _text, "token_conflict",
                                    "Bridge 同一工作区的凭据记录不一致")
                    _consistent(_values(sources, ("workspace_id", "workspaceId", "chatgpt_account_id",
                                                  "chatgptAccountId", "account_id", "accountId")),
                                _uuid, "workspace_mismatch", "Bridge 同一工作区的身份记录不一致")
                workspaces[entry_key] = item
            for item in workspaces.values():
                if item.get("status") == "left":
                    continue
                workspace_email = _consistent(_values([{"email": email}, item], ("email", "chatgpt_email")),
                                              normalize_email, "email_mismatch",
                                              "Bridge 工作区的内外邮箱不一致")
                add({**item, "email": workspace_email}, "bridge-workspace")
            if len(records) == initial:
                errors.append({"code": "access_token_missing", "message": "Bridge 账号尚无可导入的授权凭据"})
            return
        if value.get("accessToken") or value.get("access_token"):
            add(value, "chatgpt-session" if "accessToken" in value and "user" in value else "cpa" if value.get("type") == "codex" else "token-json")
            return
        errors.append({"code": "format_unsupported", "message": "未识别到支持的 OAuth 或 ChatGPT Session 凭据"})

    walk(root)
    normalized = []
    stamp = time.time() if now is None else now
    for index, (record, kind) in enumerate(records):
        try:
            item = _normalize(record, kind, now=stamp)
        except CredentialImportError as exc:
            errors.append({"index": index, "code": exc.code, "message": exc.message})
            continue
        normalized.append(item)
    return normalized, errors
