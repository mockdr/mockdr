"""ASGI middleware that assigns a request ID and logs each HTTP request."""
from __future__ import annotations

import logging
import time
import uuid

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from utils.logging import request_id_var

logger = logging.getLogger("mockdr.request")


class RequestLoggingMiddleware:
    """ASGI middleware for request-id propagation and structured request logging.

    Behaviour:
    * If the incoming request carries an ``X-Request-Id`` header its value is
      reused; otherwise a new UUID-4 is generated.
    * The request ID is stored in a :mod:`contextvars` ``ContextVar`` so any
      logger in the call stack can include it automatically.
    * An ``X-Request-Id`` response header is injected into every response.
    * After the response completes a single structured log line is emitted
      with method, path, status_code, duration_ms and request_id.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Resolve request ID: honour upstream header or generate a fresh one.
        rid = ""
        for name, value in scope.get("headers", []):
            if name.lower() == b"x-request-id":
                rid = value.decode("utf-8", errors="replace")
                break
        if not rid:
            rid = str(uuid.uuid4())

        token = request_id_var.set(rid)

        method: str = scope.get("method", "")
        path: str = scope.get("path", "")
        status_code = 0
        start = time.monotonic()

        async def send_with_rid(message: Message) -> None:
            nonlocal status_code
            if message.get("type") == "http.response.start":
                status_code = message.get("status", 0)
                headers: list[tuple[bytes, bytes]] = list(message.get("headers", []))
                headers.append((b"x-request-id", rid.encode()))
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self.app(scope, receive, send_with_rid)
        finally:
            duration_ms = round((time.monotonic() - start) * 1000, 1)
            logger.info(
                "%s %s %s %.1fms",
                method,
                path,
                status_code,
                duration_ms,
                extra={"status_code": status_code, "duration_ms": duration_ms},
            )
            request_id_var.reset(token)
