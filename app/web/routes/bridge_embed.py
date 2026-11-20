"""Authenticated, same-origin access to the private embedded Bridge workbench.

This is a fixed-upstream gateway, never an arbitrary URL proxy. Secrets live only
in explicitly requested, no-store responses; neither requests nor upstream errors
are logged. Streaming responses keep the upstream connection until completion or
browser cancellation, including model evaluation and protocol-login SSE.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

import anyio
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from starlette.background import BackgroundTask

from app.web.deps import require_admin
from app.web.routes.credential_import import _no_store, _same_origin

PREFIX = "/auth-bridge"
MAX_BODY_BYTES = 12 * 1024 * 1024
MAX_HTML_BYTES = 2 * 1024 * 1024
SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,96}$")
RESOURCE_ATTRIBUTE = re.compile(r'''(?P<start>\b(?:src|href|action)\s*=\s*["'])(?P<path>/(?!/)[^"']*)(?P<end>["'])''', re.I)
PRIVATE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": (
        "default-src 'self'; base-uri 'self'; frame-ancestors 'self'; "
        "frame-src 'self' blob:; img-src 'self' data: blob:; "
        "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; object-src 'none'"
    ),
}


def _bridge_admin(request: Request) -> dict:
    try:
        return require_admin(request)
    except HTTPException as exc:
        exc.headers = {**PRIVATE_HEADERS, **(exc.headers or {})}
        raise


def _failure(status: int, code: str, message: str, headers: dict | None = None) -> JSONResponse:
    return JSONResponse({"ok": False, "code": code, "error_code": code,
                         "message": message, "error": message}, status_code=status,
                        headers={**PRIVATE_HEADERS, **(headers or {})})


def _upstream(settings) -> str:
    """Only literal loopback addresses avoid hostname resolution and URL joining."""
    try:
        value = urlsplit(settings.auth_bridge_url)
        valid = (value.scheme == "http" and value.hostname in {"127.0.0.1", "::1"}
                 and value.username is None and value.password is None
                 and value.path in {"", "/"} and not value.query and not value.fragment
                 and value.port is not None and 1 <= value.port <= 65535)
    except ValueError:
        valid = False
    if not valid:
        raise HTTPException(503, detail={"error_code": "bridge_configuration_invalid",
                                        "message": "内嵌授权桥必须配置为固定的本机回环地址。"})
    return f"http://{value.netloc}"


def _safe_path(path: str) -> bool:
    return (not path.startswith("/") and not any(c in path for c in ("\\", "%", ":", "?", "#"))
            and all(ord(c) >= 33 and ord(c) != 127 for c in path)
            and all(part not in {".", "..", ""} for part in path.split("/"))) if path else True


def _embed_html(source: str) -> str:
    source = RESOURCE_ATTRIBUTE.sub(lambda m: m["start"] + PREFIX + m["path"] + m["end"], source)
    bootstrap = '<script src="/static/js/bridge-embedded.js"></script>'
    styling = '<link rel="stylesheet" href="/static/css/bridge-embedded.css">'
    # Install URL routing before the upstream's own scripts and style overrides last.
    source, count = re.subn(r"(<head\b[^>]*>)", lambda m: m[0] + bootstrap, source, count=1, flags=re.I)
    if not count:
        source = bootstrap + source
    source, count = re.subn(r"</head\s*>", lambda m: styling + m[0], source, count=1, flags=re.I)
    return source if count else styling + source


def _new_bridge_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(trust_env=False, follow_redirects=False,
                             timeout=httpx.Timeout(connect=3, read=180, write=30, pool=5))


async def _read_limited(response: httpx.Response, limit: int) -> bytes:
    body = bytearray()
    async for chunk in response.aiter_bytes():
        if len(body) + len(chunk) > limit:
            raise ValueError("response too large")
        body.extend(chunk)
    return bytes(body)


def _metadata_headers(response: httpx.Response) -> dict[str, str]:
    headers = {}
    for name in ("x-request-id", "x-operation-id"):
        value = response.headers.get(name, "")
        if SAFE_ID.fullmatch(value):
            headers[name] = value
    retry = response.headers.get("retry-after", "")
    if retry.isdigit() and len(retry) <= 8:
        headers["Retry-After"] = retry
    return headers


def build_bridge_embed_router() -> APIRouter:
    router = APIRouter(tags=["bridge-embed"], dependencies=[Depends(_bridge_admin), Depends(_no_store)])

    @router.get(PREFIX, include_in_schema=False)
    async def bridge_redirect():
        return RedirectResponse(PREFIX + "/", status_code=307, headers=PRIVATE_HEADERS)

    @router.api_route(PREFIX + "/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
    async def bridge_proxy(request: Request, path: str):
        settings = request.app.state.settings
        if not settings.auth_bridge_enabled:
            return _failure(503, "bridge_disabled", "内嵌授权桥已关闭，请在 Team48 配置中启用后重启。")
        if not _safe_path(path):
            return _failure(400, "invalid_bridge_path", "授权桥请求路径无效。")
        try:
            base = _upstream(settings)
        except HTTPException as exc:
            return _failure(exc.status_code, exc.detail["error_code"], exc.detail["message"])
        if len(request.scope.get("query_string", b"")) > 16384:
            return _failure(400, "invalid_bridge_query", "授权桥请求参数过长。")
        if request.method not in {"GET", "HEAD"}:
            try:
                _same_origin(request)
            except HTTPException as exc:
                return _failure(exc.status_code, "origin_mismatch", "请从当前 Team48 页面提交。")
            if not path.startswith("api/"):
                return _failure(405, "method_not_allowed", "此资源只支持读取。")
            if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                return _failure(415, "json_required", "请提交 JSON 数据。")
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > MAX_BODY_BYTES:
                body.clear()
                return _failure(413, "input_too_large", "单次授权桥请求不能超过 12 MB。")
            body.extend(chunk)
        headers = {name: request.headers[name] for name in ("accept", "content-type", "last-event-id") if name in request.headers}
        for name in ("x-request-id", "x-operation-id"):
            value = request.headers.get(name, "")
            if SAFE_ID.fullmatch(value):
                headers[name] = value
        headers["accept-encoding"] = "identity"
        url = httpx.URL(base + "/" + path)
        if request.scope.get("query_string"):
            url = url.copy_with(query=request.scope["query_string"])
        client = _new_bridge_client()
        upstream = None
        try:
            upstream = await client.send(client.build_request(request.method, url, headers=headers, content=bytes(body)), stream=True)
        except httpx.HTTPError:
            await client.aclose()
            return _failure(503, "bridge_unavailable", "内嵌授权桥暂未就绪或连接中断，请稍后重试；Team48 其它功能仍可使用。")
        except BaseException:
            with anyio.CancelScope(shield=True):
                await client.aclose()
            raise
        finally:
            body.clear()

        async def close_upstream():
            # Starlette cancels the stream task on disconnect; close even inside
            # that cancellation scope so browser cancellation releases workers.
            with anyio.CancelScope(shield=True):
                try:
                    await upstream.aclose()
                finally:
                    await client.aclose()

        response_headers = {**PRIVATE_HEADERS, **_metadata_headers(upstream)}
        if upstream.status_code >= 400:
            # Never reflect arbitrary upstream messages, traces or credential bodies.
            status = upstream.status_code
            code = "bridge_request_failed"
            try:
                data = json.loads(await _read_limited(upstream, 65536))
                candidate = data.get("code") if isinstance(data, dict) else None
                if isinstance(candidate, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{1,79}", candidate):
                    code = candidate
            except (ValueError, httpx.HTTPError):
                pass
            finally:
                await close_upstream()
            message = ("授权桥繁忙，请稍后重试。" if status == 429 else
                       "授权桥暂时无法完成请求，请检查输入或稍后重试。")
            return _failure(status, code, message, response_headers)
        if 300 <= upstream.status_code < 400:
            # The embedded application has only local static redirects. Never follow an upstream redirect.
            location = upstream.headers.get("location", "")
            await close_upstream()
            if location.startswith("/") and not location.startswith("//") and _safe_path(location.lstrip("/")):
                return RedirectResponse(PREFIX + location, status_code=upstream.status_code, headers=response_headers)
            return _failure(502, "bridge_redirect_rejected", "授权桥返回了不支持的跳转。")
        content_type = upstream.headers.get("content-type", "application/octet-stream")
        if "text/html" in content_type and request.method != "HEAD":
            try:
                source = (await _read_limited(upstream, MAX_HTML_BYTES)).decode("utf-8")
                return HTMLResponse(_embed_html(source), status_code=upstream.status_code, headers=response_headers)
            except (ValueError, UnicodeError, httpx.HTTPError):
                return _failure(502, "bridge_page_unavailable", "授权工作台页面暂时无法加载，请稍后重试。")
            finally:
                await close_upstream()
        response_headers["Content-Type"] = content_type
        disposition = upstream.headers.get("content-disposition", "")
        if disposition and disposition.isascii() and len(disposition) <= 1024 and not any(ord(c) < 32 or ord(c) == 127 for c in disposition):
            response_headers["Content-Disposition"] = disposition
        if "text/event-stream" in content_type:
            response_headers["X-Accel-Buffering"] = "no"
        if request.method == "HEAD":
            await close_upstream()
            return Response(status_code=upstream.status_code, headers=response_headers)

        async def chunks():
            try:
                async for chunk in upstream.aiter_bytes():
                    yield chunk
            except httpx.HTTPError:
                if "text/event-stream" in content_type:
                    event = json.dumps({"type": "error", "ok": False, "code": "bridge_stream_interrupted",
                                        "error": "授权桥连接中断，请核对任务结果后重试。"}, ensure_ascii=False)
                    yield ("data: " + event + "\n\n").encode()
            finally:
                await close_upstream()

        return StreamingResponse(chunks(), status_code=upstream.status_code, headers=response_headers,
                                 background=BackgroundTask(close_upstream))

    return router
