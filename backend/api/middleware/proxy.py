"""ASGI middleware for recording and replaying real vendor API responses.

Supports all eight vendors: SentinelOne, CrowdStrike, MDE, Elastic Security,
Cortex XDR, Splunk SIEM, Microsoft Sentinel, and Microsoft Graph.
"""
from __future__ import annotations

import json

import httpx
from starlette.types import ASGIApp, Receive, Scope, Send

from application.proxy import commands as proxy_commands
from application.proxy import queries as proxy_queries
from application.proxy.auth_headers import build_auth_headers
from application.proxy.token_cache import OAuth2TokenCache
from application.proxy.vendor_routing import detect_vendor, strip_prefix
from domain.proxy_recording import ProxyRecording, VendorProxyConfig
from utils.dt import utc_now
from utils.id_gen import new_id

_ERROR_UPSTREAM = json.dumps({
    "errors": [{"code": 5020001, "detail": "Upstream request failed", "title": "Bad Gateway"}],
    "data": None,
}).encode()


class RecordingProxyMiddleware:
    """ASGI middleware that can record and replay real vendor API responses.

    Three modes:
    - ``off``: no-op, all requests go to the mock as normal.
    - ``record``: detect the vendor from the URL prefix, forward the request
      to the configured real upstream with vendor-appropriate auth headers,
      persist the exchange, and return the real response.
    - ``replay``: serve from the nearest matching recording (method + path +
      vendor); fall through to the mock if no recording is found.

    Dev paths (``/_dev/``) are always passed to the mock unchanged.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        config = proxy_queries.get_config_raw()
        path: str = scope.get("path", "")

        # Dev endpoints and disabled mode always pass through.
        if config.mode == "off" or "/_dev/" in path:
            await self.app(scope, receive, send)
            return

        # Detect which vendor this request is for.
        vendor = detect_vendor(path)
        if vendor is None:
            # Unknown prefix -- fall through to mock.
            await self.app(scope, receive, send)
            return

        # Look up per-vendor config.
        vendor_cfg = config.vendors.get(vendor)
        if vendor_cfg is None or not vendor_cfg.enabled or not vendor_cfg.base_url:
            # No config for this vendor -- fall through to mock.
            await self.app(scope, receive, send)
            return

        method: str = scope.get("method", "GET")
        query_bytes: bytes = scope.get("query_string", b"")
        query_str: str = query_bytes.decode("utf-8", errors="replace") if query_bytes else ""

        token_cache: OAuth2TokenCache = proxy_queries.get_token_cache()  # type: ignore[assignment]

        if config.mode == "record":
            body = await _read_body(receive)
            succeeded = await _record_and_forward(
                method=method,
                path=path,
                query_str=query_str,
                body=body,
                vendor=vendor,
                vendor_cfg=vendor_cfg,
                token_cache=token_cache,
                send=send,
            )
            if not succeeded:
                await _send_bytes(502, _ERROR_UPSTREAM, "application/json", send)

        elif config.mode == "replay":
            recording = proxy_queries.find_recording(method, path, vendor=vendor)
            if recording is not None:
                await _send_bytes(
                    recording.response_status,
                    recording.response_body.encode(),
                    recording.response_content_type,
                    send,
                )
            else:
                # No recording -- fall through to mock.
                await self.app(scope, receive, send)


async def _read_body(receive: Receive) -> bytes:
    """Read and buffer the full HTTP request body from the ASGI receive channel."""
    chunks: list[bytes] = []
    while True:
        message = await receive()
        chunks.append(message.get("body", b""))
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


async def _record_and_forward(
    method: str,
    path: str,
    query_str: str,
    body: bytes,
    vendor: str,
    vendor_cfg: VendorProxyConfig,
    token_cache: OAuth2TokenCache,
    send: Send,
) -> bool:
    """Forward the request to the real vendor API, record the exchange, send the response."""
    # Strip mockdr prefix and build the upstream URL.
    upstream_path = strip_prefix(path, vendor)
    target_url = vendor_cfg.base_url + upstream_path
    if query_str:
        target_url += f"?{query_str}"

    # Build vendor-specific auth headers.
    try:
        auth_headers = await build_auth_headers(vendor, vendor_cfg.auth, token_cache)
    except (httpx.HTTPError, ValueError, TypeError, OSError):
        return False

    forward_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        **auth_headers,
    }

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.request(
                method=method,
                url=target_url,
                content=body,
                headers=forward_headers,
                timeout=30.0,
            )

        content_type = resp.headers.get("content-type", "application/json")
        proxy_commands.add_recording(ProxyRecording(
            id=new_id(),
            method=method,
            path=path,
            query_string=query_str,
            request_body=body.decode("utf-8", errors="replace"),
            response_status=resp.status_code,
            response_body=resp.text,
            response_content_type=content_type,
            recorded_at=utc_now(),
            base_url=vendor_cfg.base_url,
            vendor=vendor,
        ))

        await _send_bytes(resp.status_code, resp.content, content_type, send)
        return True

    except (httpx.HTTPError, ValueError, TypeError, OSError):
        return False


async def _send_bytes(status: int, body: bytes, content_type: str, send: Send) -> None:
    """Send a complete HTTP response via the ASGI send channel."""
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [(b"content-type", content_type.encode())],
    })
    await send({
        "type": "http.response.body",
        "body": body,
        "more_body": False,
    })
