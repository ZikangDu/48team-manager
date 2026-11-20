"""Durable state machine of an automated 2FA (TOTP) reset.

Remote sequence: read status -> disable the old factor -> enrol a new key ->
activate it with a code -> read status again. A lost response anywhere must
never cost the only copy of a key that may already be live, so every request
that can change the account is preceded by a committed, encrypted local record:

  preparing   a change may have started; no new key is held yet
  prepared    new key received and stored; no activation is pending
  activating  an activation is about to be / was sent; its outcome may be unknown
  activated   activation acknowledged; the key is already the account's backup
  confirmed   official status showed the new factor; the record keeps no key
  abandoned   closed by the user; the encrypted record is archived, not deleted

An open record is only ever continued. A second key is never enrolled until the
user explicitly abandons the first, and nothing here signs in: the caller hands
over a client bound to an already authenticated browser session.
"""
from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import re
import secrets

from sqlalchemy import delete, func, select, update

from app.application.settings import upsert_setting
from app.application.tokens import encrypt_secret
from app.application.totp_backup import OFFICIAL_ACTIVATED, OFFICIAL_CONFIRMED, store_official_backup
from app.core.crypto import token_cipher
from app.core.time import utcnow
from app.domain.automation import ACTIVE_STATES
from app.integrations.auth_bridge.credentials import CredentialImportError, normalize_email
from app.integrations.openai.mfa import MfaError, generate_totp, normalize_totp_secret, totp_seconds_left
from app.persistence.models.identity import Account, Workspace
from app.persistence.models.operations import Operation
from app.persistence.models.settings import SystemSetting

SCHEMA = 1
OPEN_PHASES = ("preparing", "prepared", "activating", "activated")
KEY_PHASES = ("prepared", "activating", "activated")
CLOSED_PHASES = ("confirmed", "abandoned")
OWNER_TOTP = re.compile(r"[A-Z2-7]{16,64}", flags=re.ASCII)
STAMPS = ("created_at", "updated_at", "activated_at", "confirmed_at", "abandoned_at", "exported_at")
DESCRIPTION = "自动换绑 2FA 的恢复记录（加密）"

PHASE_MESSAGES = {
    "none": "此邮箱没有自动换绑记录",
    "preparing": "换绑已开始但尚未取得新密钥，旧 2FA 可能已停用；重新发起「重设 2FA」会先读取官方状态再继续",
    "prepared": "新密钥已生成并加密保存，尚未激活（旧 2FA 已停用）；重新发起可继续激活，或放弃后重新生成",
    "activating": "激活请求已发出但结果未知，候选密钥已加密保存；重新发起会先核对官方状态，不会重新生成密钥",
    "activated": "新 2FA 已激活并保存为该邮箱的密钥备份，官方状态尚未核对完成；重新发起可完成核对",
    "confirmed": "最近一次自动换绑已核对生效，新密钥保存在该邮箱的「2FA 密钥」中",
    "abandoned": "最近一次换绑记录已放弃；没有撤销任何官方变更",
}
MESSAGES = {
    "done": "2FA 已重设并核对生效；新密钥已加密保存在本机，可在「2FA 密钥」复制或下载",
    "cancelled": "已停止；本次没有发送任何更改",
    "session_missing": "官方页面没有提供登录会话，本次未做任何更改",
    "session_identity_mismatch": "浏览器中登录的账号与所填邮箱不一致，已停止，未做任何更改",
    "session_rejected": "官方未接受当前登录会话，本次未做任何更改",
    "rate_limited": "官方提示请求过于频繁，本次未做任何更改，请稍后再试",
    "session_unavailable": "未能读取官方登录会话，本次未做任何更改",
    "status_unavailable": "未能读取官方 2FA 状态，本次未做任何更改",
    "disable_rejected": "官方未接受停用旧 2FA 的请求，账号 2FA 未变化",
    "disable_rejected_resume": "官方未接受停用旧 2FA 的请求，本次没有更改；换绑记录保留，可稍后重新发起",
    "reset_interrupted": "停用旧 2FA 的结果未知；请重新发起，程序会先读取官方状态再继续",
    "enroll_rejected": "官方未接受生成新密钥的请求，账号 2FA 未变化",
    "enroll_failed": "旧 2FA 已停用，但新密钥没有生成，账号当前可能没有 2FA；请重新发起",
    "enroll_unknown": "生成新密钥的结果未知；请重新发起，程序会先读取官方状态再继续",
    "activation_rejected": "官方未接受激活请求，新密钥尚未生效（旧 2FA 已停用）；候选密钥已保留，可重新发起继续激活",
    "activation_unconfirmed": "激活结果未能确认，候选密钥已加密保留；请重新发起核对，确认前不会再生成新密钥",
    "factor_unmatched": "官方显示已开启 2FA，但无法确认它就是本次的新密钥；请先导出候选密钥自行核对，程序没有发送任何更改",
    "confirm_pending": "新 2FA 已激活，新密钥已加密保存；官方状态暂未核对完成，可稍后重新发起完成核对",
    "confirm_mismatch": "新 2FA 已激活并已保存，但官方状态尚未显示新因子；可稍后重新发起核对，不会重新生成密钥",
    "reset_storage_failed": "本机记录没有写入成功，已停止后续步骤；换绑可能已开始，请稍后重新发起，程序会先读取官方状态再继续",
    "storage_untouched": "本机记录没有写入成功，没有发送任何更改；请稍后重新发起",
    "storage_key_kept": "本机记录没有写入成功，已停止后续步骤；候选密钥仍保存在本机换绑记录中，请稍后重新发起核对",
}


class _StorageFailure(Exception):
    """A local write could not be committed; no further remote request is sent."""


def _key(email: str) -> str:
    return "totp_reset:" + hashlib.sha256(email.encode()).hexdigest()


def _now() -> str:
    return utcnow().isoformat()


def _unreadable() -> CredentialImportError:
    return CredentialImportError("reset_unreadable", "换绑记录无法解密或格式异常，未做任何更改；请核对本机加密配置", 409)


def _decode(raw: str | None, email: str) -> dict | None:
    if raw is None:
        return None
    try:
        record = json.loads(token_cipher().decrypt(raw))
        if (not isinstance(record, dict) or record.get("schema") != SCHEMA or record.get("email") != email
                or record.get("phase") not in OPEN_PHASES + CLOSED_PHASES):
            raise ValueError()
        for name in ("session_id", "factor_id", "replaced_factor_id", "note"):
            if not isinstance(record.get(name, ""), str):
                raise ValueError()
        if record["phase"] in KEY_PHASES:
            record["secret"] = normalize_totp_secret(record.get("secret"))
            if not record.get("session_id"):
                raise ValueError()
        elif not isinstance(record.get("secret", ""), str):
            raise ValueError()
        return record
    except Exception:
        raise _unreadable() from None


async def _raw(db, email: str) -> str | None:
    row = await db.scalar(select(SystemSetting).where(SystemSetting.key == _key(email))
                          .execution_options(populate_existing=True))
    if row is None:
        return None
    if not isinstance(row.value, str) or not row.value:
        raise _unreadable()
    return row.value


async def load(db, email: str) -> dict | None:
    """Decrypted record for a normalized email, or None; unreadable records raise."""
    return _decode(await _raw(db, email), email)


async def _rollback(db) -> None:
    try:
        await db.rollback()
    except Exception:  # noqa: BLE001
        pass


async def _persist(db, email: str, record: dict, extra=None):
    """Commit the record (and an optional same-transaction write); retried briefly."""
    record["updated_at"] = _now()
    encrypted = token_cipher().encrypt(json.dumps(record, separators=(",", ":")))
    for attempt in range(3):
        try:
            result = await extra(db) if extra else None
            await upsert_setting(db, _key(email), encrypted, DESCRIPTION)
            await db.commit()
            return result
        except Exception:  # noqa: BLE001
            await _rollback(db)
            if attempt == 2:
                raise _StorageFailure() from None
            await asyncio.sleep(0.2 * (attempt + 1))


async def _discard(db, email: str) -> None:
    """Remove a record that never held a key."""
    for attempt in range(3):
        try:
            await db.execute(delete(SystemSetting).where(SystemSetting.key == _key(email)))
            await db.commit()
            return
        except Exception:  # noqa: BLE001
            await _rollback(db)
            if attempt == 2:
                raise _StorageFailure() from None
            await asyncio.sleep(0.2 * (attempt + 1))


async def _store_primary(db, email: str, secret: str, verification: str) -> int:
    """Make the key the email's backup and the stored owner 2FA of its teams (no commit)."""
    await store_official_backup(db, email=email, secret=secret, verification=verification)
    if not OWNER_TOTP.fullmatch(secret):
        return 0
    account = await db.scalar(select(Account).where(func.lower(Account.email) == email))
    if account is None:
        return 0
    synced = 0
    for workspace in await db.scalars(select(Workspace).where(Workspace.owner_account_id == account.id)):
        workspace.owner_totp_secret_encrypted = encrypt_secret(secret)
        workspace.purchase_updated_at = utcnow()
        synced += 1
    return synced


def public_state(email: str, record: dict | None) -> dict:
    if not record:
        return {"ok": True, "email": email, "phase": "none", "open": False, "has_candidate": False,
                "exported": False, "message": PHASE_MESSAGES["none"]}
    phase = record["phase"]
    view = {"ok": True, "email": email, "phase": phase, "open": phase in OPEN_PHASES,
            "has_candidate": phase in KEY_PHASES, "exported": bool(record.get("exported_at")),
            "note": str(record.get("note") or "")[:40], "message": PHASE_MESSAGES[phase]}
    for name in STAMPS:
        if isinstance(record.get(name), str) and record[name]:
            view[name] = record[name]
    return view


async def status_reset(db, *, email) -> dict:
    email = normalize_email(email)
    return public_state(email, await load(db, email))


async def open_reset(db, email) -> dict | None:
    """The record a new browser task must continue, if any. Unreadable records raise."""
    email = normalize_email(email)
    record = await load(db, email)
    return record if record and record["phase"] in OPEN_PHASES else None


async def assert_no_open_reset(db, email) -> None:
    """Called inside another writer's transaction; never commits."""
    if await open_reset(db, email) is not None:
        raise CredentialImportError("reset_pending", "此邮箱有未完成的自动换绑记录，请先完成核对或放弃该记录", 409)


async def _lock(db, email: str) -> None:
    # SQLite reserves its single writer even when the row does not exist yet.
    await db.execute(update(SystemSetting).where(SystemSetting.key == _key(email)).values(value=SystemSetting.value))


async def _busy(db, email: str) -> bool:
    return await db.scalar(select(Operation.id).where(
        Operation.op_type == "assisted_login", func.lower(Operation.email) == email,
        Operation.state.in_(("pending", *ACTIVE_STATES))).limit(1)) is not None


async def reveal_candidate(db, *, email) -> dict:
    """Plaintext of the key held by an open record; records that it was exported."""
    email = normalize_email(email)
    try:
        await _lock(db, email)
        record = await load(db, email)
        if not record or record["phase"] not in KEY_PHASES:
            raise CredentialImportError("candidate_not_found", "此邮箱没有待核对的候选密钥", 404)
        if not record.get("exported_at"):
            record["exported_at"] = _now()
            await upsert_setting(db, _key(email), token_cipher().encrypt(json.dumps(record, separators=(",", ":"))),
                                 DESCRIPTION)
        await db.commit()
    except CredentialImportError:
        await _rollback(db)
        raise
    except Exception:
        await _rollback(db)
        raise CredentialImportError("candidate_export_failed", "候选密钥未能导出，请刷新后重试", 500) from None
    return {"email": email, "secret": record["secret"], "phase": record["phase"],
            "saved_at": str(record.get("created_at") or ""),
            "verification": OFFICIAL_ACTIVATED if record["phase"] == "activated" else "candidate_unverified"}


def _archive_key(email: str) -> str:
    return "totp_reset_archive:" + hashlib.sha256(email.encode()).hexdigest()[:24] + ":" + secrets.token_hex(8)


async def abandon_reset(db, *, email, confirmed) -> dict:
    """Close an open record on the user's decision. Remote 2FA is not touched.

    An unreadable record is left exactly as it is and refused: it may hold the
    only copy of a key that is live under different encryption settings.
    """
    email = normalize_email(email)
    if confirmed is not True:
        raise CredentialImportError("confirmation_required", "请确认放弃本地换绑记录；这不会撤销官方页面上已经发生的变更", 400)
    try:
        await _lock(db, email)
        raw = await _raw(db, email)
        record = _decode(raw, email)  # raises reset_unreadable for a garbage/foreign row, leaving it untouched
        if not record or record["phase"] not in OPEN_PHASES:
            raise CredentialImportError("reset_not_open", "没有待处理的换绑记录，请刷新核对", 409)
        if await _busy(db, email):
            raise CredentialImportError("account_busy", "此邮箱有进行中的浏览器任务，请先等待完成或停止", 409)
        if record["phase"] == "activating" and not record.get("exported_at"):
            raise CredentialImportError("export_required", "激活结果未知时候选密钥可能已经生效；请先导出候选密钥再放弃记录", 409)
        archived = record["phase"] in KEY_PHASES
        if archived:
            db.add(SystemSetting(key=_archive_key(email), value=raw, description="已放弃的换绑记录（加密归档）"))
        closed = {**record, "phase": "abandoned", "abandoned_at": _now(), "abandoned_from": record["phase"],
                  "secret": "", "session_id": "", "updated_at": _now()}
        await upsert_setting(db, _key(email), token_cipher().encrypt(json.dumps(closed, separators=(",", ":"))),
                             DESCRIPTION)
        await db.commit()
    except CredentialImportError:
        await _rollback(db)
        raise
    except Exception:
        await _rollback(db)
        raise CredentialImportError("reset_save_failed", "记录未能关闭，请刷新后核对", 500) from None
    return {**public_state(email, closed), "archived": archived,
            "message": "本地换绑记录已放弃，含密钥的原记录已加密归档；没有撤销任何官方变更" if archived
            else "本地换绑记录已放弃；没有撤销任何官方变更"}


def _result(ok: bool, status: str, code: str, message: str, *, phase: str, **extra) -> dict:
    result = {"ok": ok, "success": ok, "status": status, "message": message, "phase": phase}
    if not ok:
        result.update(error_code=code, error=message)
    result.update({key: value for key, value in extra.items() if value not in (None, "")})
    return result


def _remote(exc: MfaError | None) -> dict:
    if exc is None:
        return {}
    return {"step": exc.code[:40], "remote_status": exc.status or None, "remote_code": exc.remote_code or None}


class _Run:
    def __init__(self, db, email, client, operation_id, login_proof, report, should_abort):
        self.db, self.email, self.client = db, email, client
        self.operation_id, self.login_proof = str(operation_id or ""), bool(login_proof)
        self.report, self.should_abort = report, should_abort
        self.record: dict | None = None
        self.loaded = ""     # phase of the record this run started from
        self.committed = ""  # last phase this run committed
        self.sent = False    # a request that can change the account left in this run
        self.owner_synced = 0
        self.last_stage = ""

    async def stage(self, name: str) -> None:
        self.last_stage = name
        if self.report is None:
            return
        try:
            pending = self.report(name)
            if inspect.isawaitable(pending):
                await pending
        except Exception:  # noqa: BLE001 - progress notes never decide the outcome
            await _rollback(self.db)

    def aborted(self) -> bool:
        return bool(self.should_abort and self.should_abort())

    def open_phase(self) -> str:
        record = self.record
        return record["phase"] if record and record["phase"] in OPEN_PHASES else ""

    async def save(self, extra=None):
        result = await _persist(self.db, self.email, self.record, extra)
        self.committed = self.record["phase"]
        return result

    def untouched(self, code: str, exc: MfaError | None = None) -> dict:
        phase = self.open_phase()
        return _result(False, "manual_required" if phase else "failed", code, MESSAGES[code],
                       phase=phase or "none", **_remote(exc))

    def cancelled(self) -> dict:
        return _result(False, "cancelled", "cancelled", MESSAGES["cancelled"], phase=self.open_phase() or "none")

    def storage_failure(self) -> dict:
        # Report what is durably stored, never the in-memory record that failed to commit.
        phase = self.committed or (self.loaded if self.loaded in OPEN_PHASES else "")
        if not phase and not self.sent:
            return _result(False, "failed", "reset_storage_failed", MESSAGES["storage_untouched"], phase="none")
        message = MESSAGES["storage_key_kept"] if phase in KEY_PHASES else MESSAGES["reset_storage_failed"]
        return _result(False, "manual_required", "reset_storage_failed", message, phase=phase or "none")

    async def execute(self) -> dict:
        try:
            self.record = await load(self.db, self.email)
            await self.db.commit()  # release the read transaction before any remote wait
        except CredentialImportError as exc:
            await _rollback(self.db)
            return _result(False, "failed", exc.code, exc.message, phase="unknown")
        self.loaded = self.record["phase"] if self.record else ""
        # The sign-in only proves the key that was stored when the session signed in.
        self.login_proof = self.login_proof and self.loaded in ("activating", "activated")
        await self.stage("mfa_session")
        try:
            await self.client.open_session()
        except MfaError as exc:
            code = exc.code if exc.code in ("session_missing", "session_identity_mismatch", "session_rejected",
                                            "rate_limited") else "session_unavailable"
            return self.untouched(code, exc)
        if self.aborted():
            return self.cancelled()
        phase = self.open_phase()
        if phase == "activated":
            return await self.confirm()
        if phase in ("prepared", "activating"):
            return await self.resume()
        return await self.fresh()

    async def fresh(self) -> dict:
        """No key is held: read the truth, then disable -> enrol -> activate."""
        prior = self.record if self.record and self.record["phase"] == "preparing" else None
        managed = str(self.record.get("factor_id") or "") if self.record and self.record["phase"] == "confirmed" else ""
        await self.stage("mfa_status")
        try:
            state = await self.client.state()
        except MfaError as exc:
            return self.untouched("status_unavailable", exc)
        if self.aborted():
            return self.cancelled()
        listed = state.totp_factor_ids
        if prior is not None:
            # Continue the earlier attempt; its factor is disabled again only while still listed.
            replaced = str(prior.get("replaced_factor_id") or "")
            old_factor = (replaced if replaced in listed else "") if replaced else state.active_factor_id
            old_gone = bool(replaced) and replaced not in listed
            self.record = {**prior, "replaced_factor_id": replaced or old_factor, "note": "",
                           "operation_id": self.operation_id or str(prior.get("operation_id") or "")}
        else:
            # Prefer the factor this tool last confirmed; otherwise the one the service lists first.
            old_factor = managed if managed and managed in listed else state.active_factor_id
            old_gone = False
            self.record = {"schema": SCHEMA, "email": self.email, "phase": "preparing", "attempts": 0,
                           "uncertain": False, "secret": "", "session_id": "", "factor_id": "",
                           "replaced_factor_id": old_factor, "operation_id": self.operation_id,
                           "created_at": _now(), "note": ""}
        await self.save()  # durable before the first request that can change the account
        if old_factor:
            await self.stage("mfa_disable")
            self.sent = True
            try:
                await self.client.disable(old_factor)
                old_gone = True
            except MfaError as exc:
                if exc.rejected and prior is None:
                    # Answered without acting, and nothing else was ever sent for this record.
                    await _discard(self.db, self.email)
                    self.record, self.committed = None, ""
                    return _result(False, "failed", "disable_rejected", MESSAGES["disable_rejected"],
                                   phase="none", **_remote(exc))
                if exc.rejected:
                    self.record["note"] = "disable_rejected"
                    await self.save()
                    return _result(False, "manual_required", "disable_rejected", MESSAGES["disable_rejected_resume"],
                                   phase="preparing", **_remote(exc))
                # Outcome unknown: stop here; the next run reads the official status before sending more.
                self.record["note"] = "disable_unknown"
                await self.save()
                return _result(False, "manual_required", "reset_interrupted", MESSAGES["reset_interrupted"],
                               phase="preparing", **_remote(exc))
        await self.stage("mfa_enroll")
        self.sent = True
        try:
            enrollment = await self.client.enroll()
        except MfaError as exc:
            if exc.rejected and prior is None and not old_factor:
                await _discard(self.db, self.email)
                self.record, self.committed = None, ""
                return _result(False, "failed", "enroll_rejected", MESSAGES["enroll_rejected"],
                               phase="none", **_remote(exc))
            self.record["note"] = "enroll_rejected" if exc.rejected else "enroll_unknown"
            await self.save()
            return _result(False, "manual_required", "enroll_failed",
                           MESSAGES["enroll_failed" if old_gone else "enroll_unknown"], phase="preparing", **_remote(exc))
        self.record.update(phase="prepared", secret=enrollment.secret, session_id=enrollment.session_id,
                           factor_id=enrollment.factor_id, note="")
        await self.save()  # the new key is durable before an activation is ever sent
        return await self.activate()

    async def resume(self) -> dict:
        """A key is held but not acknowledged: read the truth before sending anything."""
        record = self.record
        if record["phase"] == "activating":
            record["uncertain"] = True  # an earlier activation's outcome was never recorded
        await self.stage("mfa_status")
        try:
            state = await self.client.state()
        except MfaError as exc:
            return self.untouched("status_unavailable", exc)
        if self.live(state):
            return await self.finalize(state)
        if record["phase"] == "activating" and state.enabled and not record.get("factor_id"):
            # 2FA is on, but nothing ties it to the stored key: send nothing.
            return _result(False, "manual_required", "factor_unmatched", MESSAGES["factor_unmatched"],
                           phase="activating")
        if self.aborted():
            return self.cancelled()
        return await self.activate()

    async def activate(self) -> dict:
        record = self.record
        record.update(phase="activating", attempts=int(record.get("attempts") or 0) + 1, note="")
        await self.save()  # from here on an activation may have reached the server
        await self.stage("mfa_activate")
        left = totp_seconds_left()
        if left < 4:
            await asyncio.sleep(left + 0.7)  # never submit a code that is about to roll over
        self.sent = True
        try:
            await self.client.activate(code=generate_totp(record["secret"]), session_id=record["session_id"])
        except MfaError as exc:
            if exc.rejected and not record.get("uncertain"):
                # Every attempt so far was answered without activating: the key is stored, not live.
                record.update(phase="prepared", note="activation_rejected")
                await self.save()
                return _result(False, "manual_required", "activation_rejected", MESSAGES["activation_rejected"],
                               phase="prepared", **_remote(exc))
            record.update(uncertain=True, note="activation_rejected_retry" if exc.rejected else "activation_unknown")
            await self.save()
            return await self.confirm(exc)
        record.update(phase="activated", activated_at=_now(), note="")
        # Commit the acknowledged key as the primary copy before any further remote call.
        self.owner_synced = await self.save(
            lambda db: _store_primary(db, self.email, record["secret"], OFFICIAL_ACTIVATED)) or 0
        return await self.confirm()

    async def confirm(self, failure: MfaError | None = None) -> dict:
        record = self.record
        await self.stage("mfa_confirm")
        try:
            state = await self.client.state()
        except MfaError as exc:
            if record["phase"] == "activated":
                return _result(False, "manual_required", "confirm_pending", MESSAGES["confirm_pending"],
                               phase="activated", backup_saved=True, owner_synced=self.owner_synced, **_remote(exc))
            return _result(False, "manual_required", "activation_unconfirmed", MESSAGES["activation_unconfirmed"],
                           phase="activating", **_remote(failure or exc))
        if self.live(state):
            return await self.finalize(state)
        if record["phase"] == "activated":
            return _result(False, "manual_required", "confirm_mismatch", MESSAGES["confirm_mismatch"],
                           phase="activated", backup_saved=True, owner_synced=self.owner_synced)
        return _result(False, "manual_required", "activation_unconfirmed", MESSAGES["activation_unconfirmed"],
                       phase="activating", **_remote(failure))

    def live(self, state) -> bool:
        """Is the stored key proven to be the account's active factor?"""
        record = self.record
        factor_id = record.get("factor_id") or ""
        if self.login_proof:
            return True  # this session signed in with a code generated from the stored key
        if not state.enabled:
            return False
        if factor_id:
            return factor_id in state.totp_factor_ids
        return record["phase"] == "activated"  # acknowledged, and the service gave no id to match

    async def finalize(self, state) -> dict:
        if self.last_stage != "mfa_confirm":
            await self.stage("mfa_confirm")
        record = self.record
        secret, factor_id, stamp = record["secret"], record.get("factor_id") or "", _now()
        others = [item for item in state.totp_factor_ids if item != factor_id]
        extra_factors = len(others) if factor_id else max(0, len(state.totp_factor_ids) - 1)
        self.record = {**record, "phase": "confirmed", "confirmed_at": stamp,
                       "activated_at": record.get("activated_at") or stamp, "note": "",
                       "secret": "", "session_id": ""}
        try:
            synced = await self.save(lambda db: _store_primary(db, self.email, secret, OFFICIAL_CONFIRMED)) or 0
        except _StorageFailure:
            self.record = record  # the previous committed record still holds the key
            raise
        return _result(True, "success", "", MESSAGES["done"], phase="confirmed", backup_saved=True,
                       owner_synced=synced, extra_factors=extra_factors or None)


async def run_reset(db, *, email, client, operation_id="", login_proof=False, report=None, should_abort=None) -> dict:
    """Drive one authenticated session through the reset; the result holds no secret.

    ``login_proof`` means this very session signed in with a code generated from
    the stored candidate key. ``should_abort`` is honoured only while this run
    has not yet sent a request that can change the account.
    """
    email = normalize_email(email)
    run = _Run(db, email, client, operation_id, login_proof, report, should_abort)
    try:
        return await run.execute()
    except _StorageFailure:
        await _rollback(db)
        return run.storage_failure()
    finally:
        client.close()
