"""ASGI middleware for recording and replaying real S1 API responses."""
from __future__ import annotations

import json

import httpx
from starlette.types import ASGIApp, Receive, Scope, Send

from application.proxy import commands as proxy_commands
from application.proxy import queries as proxy_queries
from domain.proxy_recording import ProxyRecording
from utils.dt import utc_now
from utils.id_gen import new_id

_ERROR_UPSTREAM = json.dumps({
    "errors": [{"code": 5020001, "detail": "Upstream S1 request failed", "title": "Bad Gateway"}],
    "data": None,
}).encode()


class RecordingProxyMiddleware:
    """ASGI middleware that can record and replay real S1 API responses.

    Three modes:
    - ``off``: no-op, all requests go to the mock as normal.
    - ``record``: forward every request to the configured real S1 tenant,
      persist the exchange, return the real response.
    - ``replay``: serve from the nearest matching recording (method + path);
      fall through to the mock if no recording is found.

    Dev paths (``/_dev/``) are always passed to the mock unchanged.
    """

    def __init__(self, app: ASGIApp) -> None:
        """Wrap the given ASGI app.

        Args:
            app: The inner ASGI application.
        """
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Intercept HTTP requests according to the current proxy mode.

        Args:
            scope: ASGI connection scope dict.
            receive: ASGI receive callable.
            send: ASGI send callable.
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        config = proxy_queries.get_config_raw()
        path: str = scope.get("path", "")

        # Dev endpoints and disabled mode always pass through to the mock.
        if config.mode == "off" or "/_dev/" in path:
            await self.app(scope, receive, send)
            return

        method: str = scope.get("method", "GET")
        query_bytes: bytes = scope.get("query_string", b"")
        query_str: str = query_bytes.decode("utf-8", errors="replace") if query_bytes else ""

        if config.mode == "record":
            body = await _read_body(receive)
            succeeded = await _record_and_forward(
                method=method,
                path=path,
                query_str=query_str,
                body=body,
                config_base_url=config.base_url,
                config_token=config.api_token,
                send=send,
            )
            if not succeeded:
                await _send_bytes(502, _ERROR_UPSTREAM, "application/json", send)

        elif config.mode == "replay":
            recording = proxy_queries.find_recording(method, path)
            if recording is not None:
                await _send_bytes(
                    recording.response_status,
                    recording.response_body.encode(),
                    recording.response_content_type,
                    send,
                )
            else:
                # No recording — fall through to mock.
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
    config_base_url: str,
    config_token: str,
    send: Send,
) -> bool:
    """Forward the request to the real S1 tenant, record the exchange, send the response.

    Args:
        method: HTTP method.
        path: Request path (includes API prefix).
        query_str: URL query string.
        body: Raw request body bytes.
        config_base_url: Real S1 base URL.
        config_token: Real S1 API token.
        send: ASGI send callable.

    Returns:
        ``True`` if the upstream request succeeded, ``False`` otherwise.
    """
    target_url = config_base_url + path
    if query_str:
        target_url += f"?{query_str}"

    forward_headers = {
        "Authorization": f"ApiToken {config_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
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
            base_url=config_base_url,
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
