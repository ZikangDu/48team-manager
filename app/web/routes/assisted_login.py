"""Admin-only ordinary-browser assistance, never a protocol-login proxy.

Plaintext authenticator keys leave only through the explicit reveal endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
from app.web.deps import require_admin
from app.web.routes.credential_import import _payload, _same_origin, _no_store
from app.web.schemas.assisted_login import (
    AssistedLoginRequest, TotpBackupRequest, TotpResetAbandonRequest, TotpRevealRequest,
)
from app.integrations.auth_bridge.credentials import CredentialImportError


def _result(value):
    if value.get("ok") is False:
        code = str(value.get("error_code") or "request_failed")
        status = 404 if code == "not_found" else 409 if code.endswith(("busy", "conflict", "owned", "disabled", "unreadable")) else 400
        raise HTTPException(status, detail={"error_code": code, "message": value.get("message") or value.get("error") or "操作未完成"})
    return value


def build_assisted_login_router(get_db):
    router = APIRouter(prefix="/api/assisted-login", tags=["assisted-login"],
                       dependencies=[Depends(require_admin), Depends(_no_store)])

    @router.get("/capabilities")
    async def capabilities():
        return {"ok": True, "oauth": True, "password_totp": True, "browser": "ordinary_chrome",
                "security_handoff": True, "logout_handoff": True, "automatic_mfa_change": True,
                "totp_reset": True, "totp_backup": True, "concurrency": 1,
                "secret_storage": "current_task_memory_only", "reset_key_storage": "encrypted_local_record",
                "message": "使用普通 Chrome 登录；安全挑战由使用者在官方窗口完成，重设 2FA 由程序在登录后的官方会话内执行"}

    @router.post("/start", status_code=202)
    async def start(request: Request, db: AsyncSession = Depends(get_db)):
        from app.application.assisted_login import start_assisted_login
        data = await _payload(request, AssistedLoginRequest)
        return _result(await start_assisted_login(db, email=str(data.email), password=data.password.get_secret_value(),
            totp_secret=data.totp_secret.get_secret_value(), action=data.action, confirm_reset=data.confirm_reset))

    @router.post("/totp-backup")
    async def backup(request: Request, db: AsyncSession = Depends(get_db)):
        from app.application.totp_backup import save_backup
        data = await _payload(request, TotpBackupRequest)
        try:
            return await save_backup(db, email=str(data.email), secret=data.secret.get_secret_value(), confirmed=data.confirmed)
        except CredentialImportError as exc:
            raise HTTPException(exc.status_code, detail={"error_code":exc.code,"message":exc.message}) from None

    @router.post("/hints")
    async def hints(request: Request, db: AsyncSession = Depends(get_db)):
        from app.application.assisted_login import AssistedLoginError, credential_hints
        data = await _payload(request, TotpRevealRequest)
        try:
            return await credential_hints(db, email=str(data.email))
        except AssistedLoginError as exc:
            raise HTTPException(exc.status_code, detail={"error_code":exc.code,"message":exc.message}) from None

    @router.post("/totp-backup/status")
    async def backup_status(request: Request, db: AsyncSession = Depends(get_db)):
        from app.application.totp_backup import backup_state
        data = await _payload(request, TotpRevealRequest)
        try:
            return await backup_state(db, email=str(data.email))
        except CredentialImportError as exc:
            raise HTTPException(exc.status_code, detail={"error_code":exc.code,"message":exc.message}) from None

    @router.post("/totp-backup/reveal")
    async def reveal(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
        from app.application.totp_backup import reveal_backup
        data = await _payload(request, TotpRevealRequest)
        try:
            result = await reveal_backup(db, email=str(data.email))
        except CredentialImportError as exc:
            raise HTTPException(exc.status_code, detail={"error_code":exc.code,"message":exc.message}) from None
        response.headers["Content-Disposition"] = 'attachment; filename="team48-totp-backup.json"'
        return result

    @router.post("/totp-reset/status")
    async def reset_status(request: Request, db: AsyncSession = Depends(get_db)):
        from app.application.totp_reset import status_reset
        data = await _payload(request, TotpRevealRequest)
        try:
            return await status_reset(db, email=str(data.email))
        except CredentialImportError as exc:
            raise HTTPException(exc.status_code, detail={"error_code":exc.code,"message":exc.message}) from None

    @router.post("/totp-reset/reveal")
    async def reset_reveal(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
        from app.application.totp_reset import reveal_candidate
        data = await _payload(request, TotpRevealRequest)
        try:
            result = await reveal_candidate(db, email=str(data.email))
        except CredentialImportError as exc:
            raise HTTPException(exc.status_code, detail={"error_code":exc.code,"message":exc.message}) from None
        response.headers["Content-Disposition"] = 'attachment; filename="team48-totp-candidate.json"'
        return result

    @router.post("/totp-reset/abandon")
    async def reset_abandon(request: Request, db: AsyncSession = Depends(get_db)):
        from app.application.totp_reset import abandon_reset
        data = await _payload(request, TotpResetAbandonRequest)
        try:
            return await abandon_reset(db, email=str(data.email), confirmed=data.confirmed)
        except CredentialImportError as exc:
            raise HTTPException(exc.status_code, detail={"error_code":exc.code,"message":exc.message}) from None

    @router.get("/{operation_id}")
    async def status(operation_id: str, db: AsyncSession = Depends(get_db)):
        from app.application.assisted_login import status_assisted_login
        value = await status_assisted_login(db, operation_id)
        return _result(value) if value.get("error_code") == "not_found" else value

    @router.post("/{operation_id}/cancel")
    async def cancel(operation_id: str, request: Request, db: AsyncSession = Depends(get_db)):
        from app.application.assisted_login import cancel_assisted_login
        _same_origin(request)
        return _result(await cancel_assisted_login(db, operation_id))

    return router
