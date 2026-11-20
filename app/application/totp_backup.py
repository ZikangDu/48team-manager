"""Encrypted local copies of account MFA keys.

A manual backup is user-reported and never changes remote MFA. A key written by
an automated reset carries the level the official service acknowledged.
"""
import base64
import hashlib
import json
import re

from sqlalchemy import update
from app.application.settings import get_setting_value, upsert_setting
from app.core.crypto import token_cipher
from app.core.time import utcnow
from app.integrations.auth_bridge.credentials import normalize_email, CredentialImportError
from app.persistence.models.settings import SystemSetting

USER_REPORTED = "user_reported"
OFFICIAL_ACTIVATED = "official_activated"  # activation acknowledged; status check still pending
OFFICIAL_CONFIRMED = "official_confirmed"  # activation acknowledged and the status check matched
VERIFICATIONS = frozenset((USER_REPORTED, OFFICIAL_ACTIVATED, OFFICIAL_CONFIRMED))


def _key(email):
    return "user_totp_backup:" + hashlib.sha256(email.encode()).hexdigest()


def normalize_secret(value):
    if not isinstance(value, str) or len(value) > 256:
        raise CredentialImportError("invalid_totp", "请输入验证器密钥，不是六位验证码")
    secret = re.sub(r"\s+", "", value).upper().rstrip("=")
    if not re.fullmatch(r"[A-Z2-7]{16,128}", secret):
        raise CredentialImportError("invalid_totp", "请输入有效的 Base32 验证器密钥")
    try:
        decoded = base64.b32decode(secret + "=" * (-len(secret) % 8))
        if len(decoded) < 10:
            raise ValueError()
    except ValueError:
        raise CredentialImportError("invalid_totp", "验证器密钥格式不正确") from None
    return secret


def _document(raw, email):
    try:
        document = json.loads(token_cipher().decrypt(raw))
        if (not isinstance(document, dict) or document.get("email") != email
                or document.get("verification") not in VERIFICATIONS):
            raise ValueError()
        document["secret"] = normalize_secret(document.get("secret"))
        return document
    except Exception:
        raise CredentialImportError("backup_unreadable", "备份无法解密，请核对本地加密配置", 409) from None


async def save_backup(db, *, email, secret, confirmed):
    if confirmed is not True:
        raise CredentialImportError("confirmation_required", "请先确认已经在官方页面完成换绑并核对新密钥")
    email = normalize_email(email)
    secret = normalize_secret(secret)
    document = {"email": email, "secret": secret, "saved_at": utcnow().isoformat(),
                "verification": USER_REPORTED, "remote_change_performed": False}
    encrypted = token_cipher().encrypt(json.dumps(document, separators=(",", ":")))
    key = _key(email)
    try:
        await db.execute(update(SystemSetting).where(SystemSetting.key == key).values(value=SystemSetting.value))
        # A manual copy must not replace the key of an automated reset that is still open.
        from app.application.totp_reset import assert_no_open_reset
        await assert_no_open_reset(db, email)
        previous = await get_setting_value(db, key)
        if previous:
            try:
                same = _document(previous, email)["secret"] == secret
            except CredentialImportError:
                same = False
            if not same:
                # Never lose the only copy of a key: the replaced document stays, encrypted, in an archive row.
                import secrets as _secrets
                db.add(SystemSetting(key="user_totp_backup_archive:" + hashlib.sha256(email.encode()).hexdigest()[:24]
                                     + ":" + _secrets.token_hex(8), value=previous, description="被替换的验证器密钥备份（加密归档）"))
        await upsert_setting(db, key, encrypted, "使用者确认的验证器密钥备份（加密）")
        await db.commit()
    except CredentialImportError:
        await db.rollback()
        raise
    except Exception:
        await db.rollback()
        raise CredentialImportError("backup_failed", "本地备份未保存，请保留新密钥后重试", 500) from None
    return {"ok": True, "email": email, "saved_at": document["saved_at"], "verification": USER_REPORTED,
            "message": "新密钥已加密备份；此操作未修改或验证官方 2FA"}


async def store_official_backup(db, *, email, secret, verification):
    """Write the key of an automated reset inside the caller's transaction (no commit)."""
    if verification not in (OFFICIAL_ACTIVATED, OFFICIAL_CONFIRMED):
        raise ValueError("Unsupported verification level")
    email = normalize_email(email)
    document = {"email": email, "secret": normalize_secret(secret), "saved_at": utcnow().isoformat(),
                "verification": verification, "remote_change_performed": True}
    await upsert_setting(db, _key(email), token_cipher().encrypt(json.dumps(document, separators=(",", ":"))),
                         "自动换绑后官方已激活的验证器密钥（加密）")
    return document["saved_at"]


async def stored_secret(db, email) -> str:
    """Best-effort saved key for a login form left blank; never raises."""
    try:
        email = normalize_email(email)
        raw = await get_setting_value(db, _key(email))
        return _document(raw, email)["secret"] if raw else ""
    except Exception:
        return ""


async def backup_state(db, *, email):
    """Whether a key is saved for the email and how it was verified; never the key itself."""
    email = normalize_email(email)
    raw = await get_setting_value(db, _key(email))
    if not raw:
        return {"ok": True, "email": email, "exists": False}
    document = _document(raw, email)
    return {"ok": True, "email": email, "exists": True, "verification": document["verification"],
            "saved_at": str(document.get("saved_at") or "")}


async def reveal_backup(db, *, email):
    email = normalize_email(email)
    raw = await get_setting_value(db, _key(email))
    if not raw:
        raise CredentialImportError("backup_not_found", "此邮箱没有保存过验证器密钥备份", 404)
    document = _document(raw, email)
    return {"email": email, "secret": document["secret"], "saved_at": str(document.get("saved_at") or ""),
            "verification": document["verification"]}
