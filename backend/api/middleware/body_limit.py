"""Refuse request bodies larger than ``MAX_BODY_BYTES``.

Pure ASGI so the body is never buffered here: a declared ``Content-Length``
over the limit is refused before any byte is read, and a chunked body is cut
off the moment its running size passes the limit.
"""

from __future__ import annotations

import json

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from config import MAX_BODY_BYTES


class BodyLimitMiddleware:
    """413 for bodies over the configured limit."""

    def __init__(self, app: ASGIApp, limit: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.limit = limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = _content_length(scope)
        if declared is not None and declared > self.limit:
            await _reject(send, self.limit)
            return
        seen = 0
        rejected = False

        async def limited_receive() -> Message:
            nonlocal seen, rejected
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.limit and not rejected:
                    rejected = True
                    raise _TooLargeError
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _TooLargeError:
            await _reject(send, self.limit)


class _TooLargeError(Exception):
    pass


def _content_length(scope: Scope) -> int | None:
    for name, value in scope.get("headers", []):
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None


async def _reject(send: Send, limit: int) -> None:
    body = json.dumps({"error": "request body too large", "limit_bytes": limit}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
