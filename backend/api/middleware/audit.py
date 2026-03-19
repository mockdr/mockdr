"""ASGI middleware that records every HTTP request to the audit log."""
from __future__ import annotations

import time

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from domain.request_log import RequestLog
from repository.request_log_repo import request_log_repo
from utils.dt import utc_now
from utils.id_gen import new_id

_SKIP_PATH_SUFFIX = "/_dev/requests"


class RequestAuditMiddleware:
    """ASGI middleware that appends a ``RequestLog`` entry after each response.

    The ``/_dev/requests`` path is excluded to prevent infinite log growth.
    All errors are silently swallowed so a logging failure never breaks the
    main response.
    """

    def __init__(self, app: ASGIApp) -> None:
        """Wrap the given ASGI application.

        Args:
            app: The inner ASGI application to call.
        """
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Handle an ASGI request, logging the outcome after response is sent.

        Args:
            scope: ASGI connection scope dict.
            receive: ASGI receive callable.
            send: ASGI send callable.
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        if path.endswith(_SKIP_PATH_SUFFIX):
            await self.app(scope, receive, send)
            return

        method: str = scope.get("method", "")
        query_bytes: bytes = scope.get("query_string", b"")
        query_string: str = query_bytes.decode("utf-8", errors="replace") if query_bytes else ""

        # Extract token hint from Authorization header
        token_hint = ""
        for header_name, header_value in scope.get("headers", []):
            if header_name.lower() == b"authorization":
                raw = header_value.decode("utf-8", errors="replace")
                token_hint = raw[-4:] if len(raw) >= 4 else raw
                break

        status_code = 0
        start_time = time.monotonic()

        original_send = send

        async def patched_send(message: Message) -> None:
            nonlocal status_code
            if message.get("type") == "http.response.start":
                status_code = message.get("status", 0)
            await original_send(message)

        try:
            await self.app(scope, receive, patched_send)
        finally:
            try:
                duration_ms = int((time.monotonic() - start_time) * 1000)
                log = RequestLog(
                    id=new_id(),
                    timestamp=utc_now(),
                    method=method,
                    path=path,
                    query_string=query_string,
                    status_code=status_code,
                    duration_ms=duration_ms,
                    token_hint=token_hint,
                )
                request_log_repo.append(log)
            except (ValueError, TypeError, AttributeError, OSError):
                import logging
                logging.getLogger(__name__).warning(
                    "Failed to record audit log entry for %s %s",
                    method, path, exc_info=True,
                )
