"""Bounded input schemas that never echo submitted credentials."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr, StrictBool


class AssistedLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr = Field(max_length=255)
    # Blank means "use the password already stored for this account".
    password: SecretStr = Field(default=SecretStr(""), max_length=4096)
    totp_secret: SecretStr = Field(default=SecretStr(""), max_length=256)
    action: Literal["oauth", "security", "logout_all", "reset_totp"] = "oauth"
    # Required (true) for reset_totp: replacing the authenticator is never implicit.
    confirm_reset: StrictBool = False


class TotpBackupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr = Field(max_length=255)
    secret: SecretStr = Field(min_length=16, max_length=256)
    confirmed: StrictBool = False


class TotpRevealRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr = Field(max_length=255)


class TotpResetAbandonRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr = Field(max_length=255)
    confirmed: StrictBool = False


class ProtocolBatchLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=200_000)
    proxy: str | None = Field(default=None, max_length=500)
    concurrency: int | None = Field(default=None, ge=1, le=10)
    proxy_mode: Literal["auto", "inherit", "default", "profile", "custom", "direct"] = "auto"
    workspace_id: int | None = Field(default=None, gt=0, strict=True)
    proxy_profile_id: int | None = Field(default=None, gt=0, strict=True)


class ProtocolResetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr = Field(max_length=255)
    password: SecretStr = Field(default=SecretStr(""), max_length=4096)
    totp_secret: SecretStr = Field(default=SecretStr(""), max_length=256)
    confirm_reset: StrictBool = False
    proxy: str | None = Field(default=None, max_length=500)
