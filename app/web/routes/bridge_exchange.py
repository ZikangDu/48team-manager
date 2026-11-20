"""Explicit, selected credential exchange with the encrypted browser workbench."""
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import token_cipher
from app.integrations.auth_bridge.credentials import CredentialImportError, parse_credentials
from app.persistence.models.identity import Account
from app.web.deps import require_admin
from app.web.routes.credential_import import _no_store, _payload


class AccountExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    account_ids: list[Annotated[StrictInt, Field(gt=0)]] = Field(min_length=1, max_length=50)
    confirm: Literal[True]

    @field_validator("confirm", mode="before")
    @classmethod
    def explicit_confirmation(cls, value):
        if value is not True:
            raise ValueError("explicit confirmation required")
        return value


def build_bridge_exchange_router(get_db):
    router = APIRouter(prefix="/api/bridge-workbench", tags=["bridge-workbench"],
                       dependencies=[Depends(require_admin), Depends(_no_store)])

    @router.post("/accounts/export")
    async def export_accounts(request: Request, db: AsyncSession = Depends(get_db)):
        payload = await _payload(request, AccountExportRequest)
        ids = list(dict.fromkeys(payload.account_ids))
        records = {row.id: row for row in await db.scalars(select(Account).where(Account.id.in_(ids)))}
        cipher = token_cipher(request.app.state.settings)
        exported = []
        for account_id in ids:
            account = records.get(account_id)
            if account is None or account.operational_state in {"archived", "disabled"} or account.local_purpose == "disabled":
                raise HTTPException(409, detail={"error_code": "account_unavailable", "message": "所选账号不存在或已停用，请刷新列表。"})
            try:
                values = {key: cipher.decrypt(getattr(account, key + "_encrypted"))
                          for key in ("access_token", "refresh_token", "id_token", "session_token")
                          if getattr(account, key + "_encrypted")}
            except ValueError:
                raise HTTPException(409, detail={"error_code": "credential_unavailable", "message": "账号凭据无法读取，请重新授权。"}) from None
            # Expired tokens can be sent for an explicit health check, but identity must still agree.
            try:
                candidates, errors = parse_credentials({**values, "email": account.email,
                    "account_id": account.official_account_id, "user_id": account.official_user_id}, now=0)
            except CredentialImportError:
                raise HTTPException(409, detail={"error_code": "credential_unavailable", "message": "账号凭据无法读取，请重新授权。"}) from None
            if errors or len(candidates) != 1:
                raise HTTPException(409, detail={"error_code": "credential_identity_mismatch", "message": "账号与凭据身份无法核对，请先重新授权。"})
            row = candidates[0]
            exported.append({"email": row["email"], "accessToken": row["access_token"],
                "refresh_token": row["refresh_token"], "id_token": row["id_token"],
                "sessionToken": row["session_token"],
                "user": {"email": row["email"], "id": row["user_id"]},
                "account": {"id": row["workspace_id"], "planType": account.official_plan if row["plan"] == "unknown" else row["plan"]}})
        return {"ok": True, "accounts": exported, "count": len(exported)}

    return router
