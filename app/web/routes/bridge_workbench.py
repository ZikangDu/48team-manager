"""Single-account workbench. Only the private Bridge receives the saved access token."""
from __future__ import annotations

import json
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Literal

import anyio
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.core.crypto import token_cipher
from app.core.time import utcnow
from app.domain.identity.ids import workspace_official_id
from app.domain.workspaces.names import resolve_display_name
from app.integrations.auth_bridge.credentials import parse_credentials
from app.integrations.auth_bridge.login_client import BridgeError, normalize_bridge_url
from app.integrations.auth_bridge.supervisor import bridge_supervisor
from app.persistence.models.identity import Account, Workspace, WorkspaceMembership
from app.web.deps import require_admin
from app.web.routes.credential_import import _no_store, _payload

MAX_TIMESTAMP = 253402300799  # Last UTC second representable by datetime.


class HealthRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvaluationRequest(HealthRequest):
    question: Literal["candy", "pelican"]
    model: str = Field(default="gpt-6-astra", pattern=r"^[A-Za-z0-9._-]{1,100}$")
    reasoning_effort: Literal["default", "none", "minimal", "low", "medium", "high", "xhigh", "max"] = "medium"


def _error(status, code, message):
    return HTTPException(status, detail={"error_code": code, "message": message})


def _pinned_proxy(model):
    # Some legacy bindings have an ID without a usable URL. Keep them pinned.
    return case((func.trim(model.proxy) != "", func.trim(model.proxy)),
                (or_(model.proxy_profile_id.is_not(None), model.sub2api_proxy_id.is_not(None),
                     model.proxy_source == "workspace_owner", model.proxy_instance_key != ""), "unresolved"))


def _accounts_query(*, credentials=False):
    owner = aliased(Account)
    owner_proxy = _pinned_proxy(owner)
    inherited = (select(owner_proxy).select_from(WorkspaceMembership)
                 .join(Workspace, Workspace.id == WorkspaceMembership.workspace_id)
                 .join(owner, owner.id == Workspace.owner_account_id)
                 .where(WorkspaceMembership.account_id == Account.id,
                        WorkspaceMembership.membership_state.in_(("joined", "invited")),
                        Workspace.status == "active", owner_proxy.is_not(None))
                 .order_by(case((WorkspaceMembership.membership_state == "joined", 0), else_=1), Workspace.id)
                 .limit(1).correlate(Account).scalar_subquery())
    fixed = func.coalesce(_pinned_proxy(Account), case((Account.local_purpose == "child", inherited)))
    fields = [Account.id, Account.email, Account.official_plan.label("plan"), Account.auth_state,
              Account.local_purpose.label("purpose"), fixed.label("fixed_proxy"),
              func.coalesce(Account.access_token_encrypted != "", False).label("has_access_token")]
    if credentials:
        fields.extend((Account.official_user_id, Account.official_account_id, Account.access_token_encrypted))
    return select(*fields).where(Account.operational_state.not_in(("archived", "disabled")), Account.local_purpose != "disabled")


def _proxy_compatible(proxy, settings):
    if not proxy:
        return True
    if not settings.auth_bridge_managed:
        return False
    # A standalone/adopted Bridge has its own outbound configuration.
    try:
        return bridge_supervisor.uses_fixed_proxy(normalize_bridge_url(settings.auth_bridge_url), proxy)
    except ValueError:
        return False


async def _account(db, account_id, *, credentials=False):
    row = (await db.execute(_accounts_query(credentials=credentials).where(Account.id == account_id))).one_or_none()
    if row is None:
        raise _error(404, "account_not_found", "账号不存在或已停用。")
    return row


def _bridge_account(account, settings):
    if not settings.auth_bridge_enabled:
        raise _error(503, "bridge_disabled", "授权内核已关闭。")
    try:
        base = normalize_bridge_url(settings.auth_bridge_url)
    except BridgeError:
        raise _error(503, "bridge_configuration_invalid", "授权内核地址无效。") from None
    if not _proxy_compatible(account.fixed_proxy, settings):
        raise _error(409, "proxy_mismatch", "无法核对此账号的固定代理出口。请在账号详情核对代理，再选择「检查授权」或「刷新额度」。")
    if not account.has_access_token:
        raise _error(409, "access_token_missing", "请先为此账号保存有效授权。")
    try:
        access = token_cipher(settings).decrypt(account.access_token_encrypted)
    except ValueError:
        raise _error(409, "credential_unavailable", "账号凭据无法读取，请重新授权。") from None
    # Reuse the importer’s consistency checks, including contradictory JWT claims.
    # The health request itself determines whether an expired credential still works.
    records, errors = parse_credentials({"email": account.email, "access_token": access,
        "account_id": account.official_account_id, "user_id": account.official_user_id}, now=0)
    if errors or len(records) != 1 or len(access) > 32768:
        raise _error(409, "credential_identity_mismatch", "凭据身份与账号档案无法核对，请重新授权。")
    record = records[0]
    plan = record["plan"] if record["plan"] != "unknown" else account.plan
    return base, {"accessToken": access, "accountId": record["workspace_id"], "planType": plan}


def _bridge_client():
    return httpx.AsyncClient(trust_env=False, follow_redirects=False,
                             timeout=httpx.Timeout(180, connect=4, pool=5))


@asynccontextmanager
async def _bridge_response(base, path, payload):
    client = _bridge_client()
    response = None
    try:
        response = await client.send(client.build_request("POST", base + path, json=payload), stream=True)
        if response.status_code == 429:
            raise _error(429, "bridge_busy", "授权内核繁忙，请稍后重试。")
        if response.status_code != 200:
            raise _error(502, "bridge_request_failed", "授权内核未能完成这次请求。")
        yield response
    except httpx.HTTPError:
        raise _error(503, "bridge_unavailable", "授权内核连接中断，请稍后重试。") from None
    finally:
        with anyio.CancelScope(shield=True):
            try:
                if response is not None:
                    await response.aclose()
            finally:
                await client.aclose()


def _percent(usage, key):
    window = usage.get(key)
    value = window.get("usedPercent") if isinstance(window, dict) else None
    return value if type(value) in (int, float) and 0 <= value <= 100 else None


def _reset_time(usage, key):
    window = usage.get(key)
    if not isinstance(window, dict):
        return None
    stamp = window.get("resetAt")
    if not stamp:
        fetched, delay = usage.get("fetchedAt"), window.get("resetAfterSeconds")
        if (type(fetched) in (int, float) and 0 < fetched <= MAX_TIMESTAMP * 1000
                and type(delay) in (int, float) and 0 < delay <= MAX_TIMESTAMP):
            stamp = fetched / 1000 + delay
    if type(stamp) not in (int, float) or not 0 < stamp <= MAX_TIMESTAMP:
        return None
    return datetime.fromtimestamp(stamp, tz=timezone.utc).isoformat()


def _login_time(value):
    # The embedded Bridge emits Unix milliseconds. Recognize older seconds or zoned ISO values.
    if isinstance(value, str):
        value = value.strip()
        if len(value) > 48:
            return None
        if re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", value):
            value = float(value)
        else:
            try:
                stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
                return stamp.astimezone(timezone.utc) if stamp.tzinfo is not None else None
            except (ValueError, OverflowError):
                return None
    if type(value) not in (int, float) or not 0 < value <= MAX_TIMESTAMP * 1000:
        return None
    seconds = value / 1000 if value >= 10**10 else value
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


def _device_summary(row, status):
    probe = row.get("devicesStatus") if status == 200 else None
    probe = probe if type(probe) is int and 100 <= probe <= 599 else None
    result = {"devices_status": probe, "device_count": None, "app_session_count": None,
              "first_login_at": None, "last_login_at": None}
    if probe != 200:
        return result
    count, devices = row.get("deviceCount"), row.get("devices")
    if devices is not None:
        if not isinstance(devices, list) or not all(isinstance(device, dict) for device in devices):
            return result
        if count is None:
            count = len(devices)
        elif count != len(devices):
            return result
    if type(count) is not int or count < 0:
        return result
    result["device_count"] = count
    sessions = row.get("appSessionCount")
    if type(sessions) is int and sessions >= 0 and (count or sessions == 0):
        result["app_session_count"] = sessions
    if count:
        for key, field, device_field, aggregate in (
            ("first_login_at", "firstLoginAt", "createdAt", min),
            ("last_login_at", "lastLoginAt", "lastLoginAt", max),
        ):
            stamp = _login_time(row.get(field))
            if stamp is None and devices:
                times = (_login_time(device.get(device_field)) for device in devices)
                stamp = aggregate((item for item in times if item is not None), default=None)
            result[key] = stamp.isoformat() if stamp is not None else None
    return result


async def _health_summary(response):
    malformed = _error(502, "bridge_response_invalid", "授权内核返回了无法识别的测活结果。")
    raw = bytearray()
    async for chunk in response.aiter_bytes():
        if len(raw) + len(chunk) > 128 * 1024:
            raise malformed
        raw.extend(chunk)
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        raise malformed from None
    rows = data.get("results") if isinstance(data, dict) and data.get("ok") is True else None
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise malformed
    row = rows[0]
    status = row.get("status")
    if "status" not in row or type(row.get("index")) is not int or row["index"] != 0 or (status is not None and
            (type(status) is not int or not 100 <= status <= 599)):
        raise malformed
    usage = row.get("usage") if status == 200 and isinstance(row.get("usage"), dict) else {}
    devices = _device_summary(row, status)
    five_hour, seven_day = _percent(usage, "fiveHour"), _percent(usage, "sevenDay")
    healthy = status == 200 and (five_hour is not None or seven_day is not None or devices["device_count"] is not None)
    message = {200: "会话可用。" if healthy else "官方返回 HTTP 200，但缺少可核对的额度或设备信息。",
               401: "授权已失效，请重新授权。", 403: "访问受限。",
               429: "请求频率受限，请稍后重试。", None: "未能连接官方服务。"}.get(status, "本次测活未通过。")
    return {"ok": True, "healthy": healthy, "status": status, "message": message, "checked_at": utcnow().isoformat(),
            **devices,
            "quota": {"five_hour_used_percent": five_hour, "seven_day_used_percent": seven_day,
                     "five_hour_resets_at": _reset_time(usage, "fiveHour"),
                     "seven_day_resets_at": _reset_time(usage, "sevenDay")}}


def _sse(data):
    return "data: " + json.dumps(data, ensure_ascii=False, allow_nan=False) + "\n\n"


def _evaluation_event(event, request, credential):
    kind = event["type"]
    if kind == "error":
        reason = event.get("error")
        message = "模型评测未完成，请核对授权、模型和思考程度后重试。"
        if isinstance(reason, str):
            http = re.fullmatch(r"模型请求失败（HTTP ([1-5][0-9]{2})）", reason)
            if http:
                message = f"模型接口返回 HTTP {http[1]}，本次评测未完成。"
            elif reason.startswith("模型接口不接受所选思考程度"):
                message = "模型接口不支持所选思考程度，请更换档位后重试。"
            elif reason.startswith("模型请求超时"):
                message = "等待模型响应超时，请稍后重试。"
        return {"type": "error", "error": message}
    if kind == "phase" and event.get("phase") in ("queued", "connecting", "waiting"):
        return {"type": kind, "phase": event["phase"]}
    if kind not in ("delta", "complete"):
        raise ValueError
    key = "delta" if kind == "delta" else "output"
    output = event.get(key)
    if not isinstance(output, str) or len(output) > 256 * 1024 or credential in output:
        raise ValueError
    result = {"type": kind, key: output}
    for metric in ("firstTokenMs", "durationMs", "outputChars", "outputTokens"):
        value = event.get(metric)
        if type(value) in (int, float) and 0 <= value <= 2**53:
            result[metric] = value
    if kind == "complete":
        status = event.get("status")
        if status not in ("passed", "wrong_answer", "invalid_format", "manual_review"):
            raise ValueError
        result.update(status=status, model=request.model, question=request.question, reasoningEffort=request.reasoning_effort)
        for field in ("html", "answer"):
            value = event.get(field)
            if isinstance(value, str) and len(value) <= 256 * 1024 and credential not in value:
                result[field] = value
    return result


async def _evaluation_events(base, account, evaluation):
    credential = account["accessToken"]
    previous_delta_tail = ""
    try:
        body = {"account": account, "model": evaluation.model, "question": evaluation.question,
                "reasoningEffort": evaluation.reasoning_effort}
        async with _bridge_response(base, "/api/model-evaluation", body) as response:
            if response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "text/event-stream":
                raise ValueError
            async for line in response.aiter_lines():
                if line.startswith(":"):
                    yield ": heartbeat\n\n"
                elif line.startswith("data:"):
                    if len(line) > 4 * 1024 * 1024:
                        raise ValueError
                    event = _evaluation_event(json.loads(line[5:]), evaluation, credential)
                    if event["type"] == "delta":
                        # A malformed service could echo a credential across multiple SSE frames.
                        adjacent = previous_delta_tail + event["delta"]
                        if credential in adjacent:
                            raise ValueError
                        previous_delta_tail = adjacent[-(len(credential) - 1):]
                    yield _sse(event)
                    if event["type"] in ("complete", "error"):
                        return
    except HTTPException as exc:
        yield _sse({"type": "error", "error": exc.detail["message"]})
        return
    except (KeyError, ValueError, TypeError, RecursionError):
        pass
    yield _sse({"type": "error", "error": "评测数据中断，未收到完整结果。"})


class EvaluationStream(StreamingResponse):
    async def stream_response(self, send):
        # A failed ASGI send can leave the generator suspended at yield.
        try:
            await super().stream_response(send)
        finally:
            with anyio.CancelScope(shield=True):
                await self.body_iterator.aclose()


def build_bridge_workbench_router(get_db):
    router = APIRouter(prefix="/api/bridge-workbench/accounts", tags=["bridge-workbench"],
                       dependencies=[Depends(require_admin), Depends(_no_store)])

    @router.get("")
    async def accounts(request: Request, db: AsyncSession = Depends(get_db)):
        rows = await db.execute(_accounts_query().order_by(Account.email))
        return {"ok": True, "accounts": [{"id": row.id, "email": row.email, "plan": row.plan,
                "auth_state": row.auth_state, "purpose": row.purpose, "has_access_token": row.has_access_token,
                "has_fixed_proxy": bool(row.fixed_proxy),
                "proxy_compatible": _proxy_compatible(row.fixed_proxy, request.app.state.settings)} for row in rows]}

    @router.get("/{account_id}/workspaces")
    async def workspaces(account_id: int, skip_personal: bool = False, db: AsyncSession = Depends(get_db)):
        account_query = _accounts_query().add_columns(Account.official_account_id).where(Account.id == account_id)
        account = (await db.execute(account_query)).one_or_none()
        if account is None:
            raise _error(404, "account_not_found", "账号不存在或已停用。")
        credential_id = workspace_official_id(account.official_account_id) if account.has_access_token else None
        query = (select(Workspace, WorkspaceMembership.official_role, WorkspaceMembership.membership_state)
                 .outerjoin(WorkspaceMembership, and_(WorkspaceMembership.workspace_id == Workspace.id,
                                                       WorkspaceMembership.account_id == account_id))
                 .where(or_(Workspace.owner_account_id == account_id, WorkspaceMembership.account_id == account_id,
                            func.lower(Workspace.official_workspace_id) == credential_id if credential_id else False))
                 .order_by(Workspace.id))
        results = []
        credential_is_registered_team = False
        credential_has_membership_record = False
        for workspace, role, state in await db.execute(query):
            owner = workspace.owner_account_id == account_id
            official_id = workspace_official_id(workspace.official_workspace_id)
            matches_credential = bool(credential_id and official_id == credential_id)
            if matches_credential:
                credential_is_registered_team = True
                if owner or state in {"joined", "invited", "removed"}:
                    credential_has_membership_record = True
            if not owner and state not in {"joined", "invited"}:
                continue
            results.append({"id": workspace.id, "name": resolve_display_name(workspace)["name"],
                            "kind": "team", "source": "registration", "official_workspace_id": official_id,
                            "role": "owner" if owner else role, "state": workspace.status if owner else state})
        # Imports retain a single selected grant. Its UUID and exact official plan
        # describe that record only. It has no local team, role or seat to link to.
        if credential_id and not credential_has_membership_record:
            if credential_is_registered_team or account.plan in {"team", "business"}:
                kind, name = "team", "团队工作区"
            elif account.plan in {"free", "plus", "pro"}:
                kind, name = "personal", "个人空间"
            else:
                kind, name = "unknown", "已保存授权的工作区"
            if not skip_personal or kind != "personal":
                results.append({"id": None, "name": name, "kind": kind, "source": "authorization",
                                "official_workspace_id": credential_id, "role": None, "state": "saved"})
        return {"ok": True, "workspaces": results}

    @router.post("/{account_id}/health")
    async def health(account_id: int, request: Request, db: AsyncSession = Depends(get_db)):
        await _payload(request, HealthRequest)
        base, account = _bridge_account(await _account(db, account_id, credentials=True), request.app.state.settings)
        await db.rollback()  # Return the read connection before waiting for the remote probe.
        payload = {"accounts": [account], "includeUsage": True, "includeDevices": True, "includeTrial": False}
        async with _bridge_response(base, "/api/session-health", payload) as response:
            return await _health_summary(response)

    @router.post("/{account_id}/evaluation")
    async def evaluate(account_id: int, request: Request, db: AsyncSession = Depends(get_db)):
        evaluation = await _payload(request, EvaluationRequest)
        base, account = _bridge_account(await _account(db, account_id, credentials=True), request.app.state.settings)
        if str(account["planType"]).lower() == "free":
            raise _error(409, "free_plan", "免费账号不支持模型评测。")
        await db.rollback()  # Reading the stream can take minutes and needs no local transaction.
        return EvaluationStream(_evaluation_events(base, account, evaluation), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store", "Pragma": "no-cache", "X-Accel-Buffering": "no"})

    return router
