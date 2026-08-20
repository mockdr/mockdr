"""ASGI middleware that serves ``HEAD`` from the matching ``GET`` route.

RFC 9110 §9.3.2 makes ``HEAD`` mandatory wherever ``GET`` is served, and every
mocked vendor honours it — health checks and link-checkers lean on it. The
routers here register ``GET`` alone, and this FastAPI version does not add the
implicit ``HEAD`` that Starlette's own ``Route`` does, so a ``HEAD`` request
fell through to the unmatched-route fallback and came back ``405``.

Rewriting the method and discarding the body keeps one implementation per
endpoint rather than a second ``HEAD`` handler beside every ``GET``.
"""
from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send


class HeadMethodMiddleware:
    """Answer ``HEAD`` with the ``GET`` response's status and headers, no body."""

    def __init__(self, app: ASGIApp) -> None:
        """Store the wrapped ASGI application."""
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Serve a HEAD request from its GET counterpart.

        Args:
            scope:   ASGI connection scope.
            receive: ASGI receive channel.
            send:    ASGI send channel.
        """
        if scope["type"] != "http" or scope["method"] != "HEAD":
            await self.app(scope, receive, send)
            return

        body_closed = False

        async def send_without_body(message: Message) -> None:
            """Forward the response, replacing the body with an empty one."""
            nonlocal body_closed
            if message["type"] != "http.response.body":
                await send(message)
                return
            # One empty terminating chunk, then swallow whatever else the
            # handler streams — the response is already complete, and
            # forwarding more would be a protocol error.
            if not body_closed:
                body_closed = True
                await send({"type": "http.response.body", "body": b""})

        await self.app({**scope, "method": "GET"}, receive, send_without_body)
