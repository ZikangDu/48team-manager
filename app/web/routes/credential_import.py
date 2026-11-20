"""Admin-only local authentication tools; secret inputs never enter validation responses."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.application import credential_import
from app.web.deps import require_admin
from app.web.schemas.credential_import import CredentialCommitRequest, CredentialPreviewRequest

MAX_BODY_BYTES = 6 * 1024 * 1024  # Includes the JSON envelope around a 5 MB document.


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("Non-finite JSON value")


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def _same_origin(request: Request) -> None:
    # A browser request must come from this exact origin, including its scheme.
    # Origin-less CLI clients still need the existing administrator session.
    if request.headers.get("sec-fetch-site", "").lower() in {"cross-site", "same-site"}:
        raise HTTPException(403, detail={"error_code": "origin_mismatch", "message": "请从本机后台页面提交。"})
    origin = request.headers.get("origin")
    if origin is not None:
        try:
            parsed = urlsplit(origin)
            expected = urlsplit(str(request.url))
            default_ports = {"http": 80, "https": 443}
            valid = (
                bool(origin) and not any(ord(char) < 33 or ord(char) == 127 for char in origin)
                and parsed.scheme in default_ports and parsed.scheme == expected.scheme
                and parsed.hostname == expected.hostname
                and (parsed.port or default_ports[parsed.scheme]) == (expected.port or default_ports[expected.scheme])
                and parsed.username is None and parsed.password is None
                and not parsed.path and not parsed.query and not parsed.fragment
                and "?" not in origin and "#" not in origin
            )
        except ValueError:
            valid = False
        if not valid:
            raise HTTPException(403, detail={"error_code": "origin_mismatch", "message": "请从本机后台页面提交。"})


async def _payload(request: Request, model):
    _same_origin(request)
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(415, detail={"error_code": "json_required", "message": "请提交 JSON 数据。"})
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_BODY_BYTES:
            body.clear()
            raise HTTPException(413, detail={"error_code": "input_too_large", "message": "单次输入不能超过 5 MB。"})
        body.extend(chunk)
    try:
        return model.model_validate(json.loads(body, object_pairs_hook=_unique_object, parse_constant=_reject_constant))
    except (ValueError, UnicodeError, ValidationError, RecursionError):
        # Pydantic's normal 422 detail includes the rejected input. Never expose
        # password, TOTP, or token documents in a response or exception message.
        raise HTTPException(400, detail={"error_code": "invalid_input", "message": "输入格式不正确，请检查必填字段和 JSON 格式。"}) from None
    finally:
        body.clear()


def _check_result(result: dict) -> dict:
    if result.get("ok") is False and result.get("error_code"):
        code = result["error_code"]
        status = 404 if code == "not_found" else 409 if code in {
            "account_busy", "browser_busy", "bridge_busy", "credential_revision_conflict",
            "draft_expired", "draft_consumed", "remote_refresh_owned", "preview_busy",
        } else 400
        raise HTTPException(status, detail={"error_code": code, "message": result.get("message") or result.get("error") or "操作未完成。"})
    return result


def _import_error(exc):
    raise HTTPException(exc.status_code, detail={"error_code": exc.code, "message": str(exc)}) from None


def build_credential_import_router(get_db) -> APIRouter:
    router = APIRouter(prefix="/api", tags=["credential-import"], dependencies=[Depends(require_admin), Depends(_no_store)])

    @router.post("/credential-import/preview")
    async def preview(request: Request, db: AsyncSession = Depends(get_db)):
        payload = await _payload(request, CredentialPreviewRequest)
        try:
            return await credential_import.preview_import(db, payload.content)
        except credential_import.CredentialImportError as exc:
            _import_error(exc)

    @router.post("/credential-import/commit")
    async def commit(request: Request, db: AsyncSession = Depends(get_db)):
        payload = await _payload(request, CredentialCommitRequest)
        try:
            return await credential_import.commit_import(
                db, payload.draft_id, payload.selected_ids, verify_quota=payload.verify_quota,
            )
        except credential_import.CredentialImportError as exc:
            _import_error(exc)

    @router.delete("/credential-import/preview/{draft_id}")
    async def discard(draft_id: str, request: Request):
        _same_origin(request)
        try:
            credential_import.discard_preview(draft_id)
        except credential_import.CredentialImportError as exc:
            _import_error(exc)
        return {"ok": True}

    return router
