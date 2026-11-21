"""Save completed workbench authorizations through the guarded local importer."""
from sqlalchemy import func, select

from app.application import credential_import
from app.application.managed_auth import AuthRouteError, member_workspaces, resolve_auth_route
from app.application.tokens import decrypt_secret
from app.core.proxy import normalize_proxy_url
from app.integrations.auth_bridge.credentials import CredentialImportError, parse_credentials
from app.persistence.models.identity import Account


async def save_authorizations(db, records):
    candidates, errors = parse_credentials({"accounts": records})
    groups = {}
    for candidate in candidates:
        groups.setdefault(candidate["email"], []).append(candidate)
    results = [{"status": "blocked", "code": item.get("code", "invalid_credential"),
                "message": "有一项授权无法解析，请使用手动保存核对。"} for item in errors]
    for email, choices in groups.items():
        existing = await db.scalar(select(Account).where(func.lower(Account.email) == email))
        preferred = existing.official_account_id if existing else None
        teams = await member_workspaces(db, email, existing)
        known = {team.official_workspace_id for team in teams}
        matching = [item for item in choices if item["workspace_id"] == preferred] if preferred else []
        if not matching:
            matching = [item for item in choices if item["workspace_id"] in known]
        if not matching and not preferred and not known:
            business = [item for item in choices if item["plan"] in {"team", "business", "enterprise"}]
            matching = business or choices
        # Duplicate representations of the same bundle are harmless; different
        # workspaces/bundles require the user's manual selection.
        matching = list({tuple(item.get(key) for key in ("workspace_id", "access_token", "refresh_token", "session_token")): item
                         for item in matching}.values())
        if len(matching) != 1:
            results.append({"email": email, "status": "blocked", "code": "workspace_selection_required",
                            "message": "无法唯一确定工作区，请点击「保存结果到 Team48」选择。"})
            continue
        candidate = matching[0]
        if existing and existing.refresh_token_encrypted and not candidate["refresh_token"]:
            results.append({"email": email, "status": "blocked", "code": "refresh_token_missing",
                            "message": "本次结果缺少刷新令牌，已保留原授权，请手动核对。"})
            continue
        try:
            selected_team = next((team for team in teams if team.official_workspace_id == candidate["workspace_id"]), None)
            route = await resolve_auth_route(db, email, workspace_id=selected_team.id if selected_team else None)
        except AuthRouteError as exc:
            results.append({"email": email, "status": "blocked", "code": exc.code, "message": exc.message})
            continue
        if existing and existing.official_account_id == candidate["workspace_id"]:
            try:
                unchanged = all((decrypt_secret(getattr(existing, key + "_encrypted")) or "") == (candidate.get(key) or "")
                                for key in ("access_token", "refresh_token", "id_token", "session_token"))
            except ValueError:
                unchanged = False
            if unchanged and (normalize_proxy_url(existing.proxy) or "") == route.proxy:
                from app.application.authorization_followup import enqueue
                account_id = existing.id
                try:
                    followup = await enqueue(db, account_id)
                except Exception:
                    await db.rollback()
                    followup = {"queued": False, "message": "授权已保存，后台检查未排队，请在任务记录核对。"}
                results.append({"email": email, "status": "unchanged", "account_id": account_id, "followup": followup})
                continue
        draft = None
        try:
            draft = await credential_import.preview_import(db, candidate, expected_email=email)
            allowed = [item for item in draft.get("candidates", []) if item.get("allowed")]
            if len(allowed) != 1 or draft.get("errors"):
                blocked = next((item for item in draft.get("candidates", []) if not item.get("allowed")), {})
                error = blocked.get("error") or {}
                results.append({"email": email, "status": "blocked", "code": error.get("code", "candidate_blocked"),
                                "message": error.get("message", "授权未自动覆盖，请手动核对。")})
                continue
            saved = await credential_import.commit_import(db, draft["draft_id"], [allowed[0]["id"]], auth_route=route, manage_after_import=True)
            results.append({"email": email, "status": "saved", "account_id": saved["imported"][0]["account_id"],
                            "followup": saved["followups"][0] if saved["followups"] else None})
        except CredentialImportError as exc:
            results.append({"email": email, "status": "blocked", "code": exc.code, "message": exc.message})
        finally:
            if draft and draft.get("draft_id"):
                try:
                    credential_import.discard_preview(draft["draft_id"])
                except CredentialImportError:
                    pass
    return {"ok": True, "saved": sum(item["status"] == "saved" for item in results),
            "blocked": sum(item["status"] == "blocked" for item in results), "results": results}
