"""Admin-only browser-free protocol auth through the local GPTAuthBridge."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.web.deps import require_admin
from app.web.routes.credential_import import _no_store, _payload, _same_origin
from app.web.schemas.assisted_login import ProtocolBatchLoginRequest, ProtocolResetRequest


def _raise(exc):
    raise HTTPException(exc.status_code, detail={"error_code": exc.code, "message": exc.message}) from None


def build_protocol_auth_router(get_db) -> APIRouter:
    router = APIRouter(prefix="/api/protocol-auth", tags=["protocol-auth"],
                       dependencies=[Depends(require_admin), Depends(_no_store)])

    @router.get("/capabilities")
    async def capabilities():
        from app.application.protocol_auth import ProtocolAuthError, _bridge
        from app.integrations.auth_bridge.login_client import BridgeError
        try:
            status = await _bridge().status()
        except ProtocolAuthError as exc:
            return {"ok": True, "available": False, "error_code": exc.code, "message": exc.message}
        except BridgeError as exc:
            return {"ok": True, "available": False, "error_code": exc.code, "message": exc.message}
        return {"ok": True, "available": True, "task_concurrency": status["task_concurrency"],
                "totp_reset_version": status.get("totp_reset_version"),
                "message": "授权桥已连接，可协议批量登录与重设 2FA"}

    @router.post("/batch-login", status_code=202)
    async def batch_login(request: Request, db: AsyncSession = Depends(get_db)):
        from app.application.protocol_auth import ProtocolAuthError, start_batch_login
        data = await _payload(request, ProtocolBatchLoginRequest)
        try:
            return await start_batch_login(db, text=data.text, proxy=data.proxy, concurrency=data.concurrency)
        except ProtocolAuthError as exc:
            _raise(exc)

    @router.post("/reset", status_code=202)
    async def reset(request: Request, db: AsyncSession = Depends(get_db)):
        from app.application.protocol_auth import ProtocolAuthError, start_protocol_reset
        data = await _payload(request, ProtocolResetRequest)
        try:
            return await start_protocol_reset(db, email=str(data.email), password=data.password.get_secret_value(),
                totp_secret=data.totp_secret.get_secret_value(), confirm_reset=data.confirm_reset, proxy=data.proxy)
        except ProtocolAuthError as exc:
            _raise(exc)

    @router.get("/{operation_id}")
    async def status(operation_id: str, db: AsyncSession = Depends(get_db)):
        from app.application.protocol_auth import status_protocol
        value = await status_protocol(db, operation_id)
        if value.get("error_code") == "not_found":
            raise HTTPException(404, detail={"error_code": "not_found", "message": value.get("message")})
        return value

    @router.post("/{operation_id}/cancel")
    async def cancel(operation_id: str, request: Request, db: AsyncSession = Depends(get_db)):
        from app.application.protocol_auth import cancel_protocol
        _same_origin(request)
        value = await cancel_protocol(db, operation_id)
        if value.get("error_code") == "not_found":
            raise HTTPException(404, detail={"error_code": "not_found", "message": value.get("message")})
        return value

    return router
