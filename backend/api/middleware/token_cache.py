"""Keep a token response out of every cache between here and the client.

RFC 6749 §5.1: the authorization server *must* answer a token request with
``Cache-Control: no-store``, and §5.1 adds ``Pragma: no-cache`` for the
caches that predate it. Every OAuth mount here answered without either, so a
proxy or a client library following its own cache rules could keep a bearer
token and hand it out again — which is the reason the requirement exists,
and the reason a client built against this mock would not have been designed
around it.

Pure ASGI, and scoped by path: only the token endpoints each mount publishes
are touched, never the resources they protect.
"""

from __future__ import annotations

import re

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

#: Every path that mints a token here — the bare and tenant-scoped Entra
#: forms, and Falcon's own.
_TOKEN_PATH = re.compile(r"/oauth2(?:/v2\.0)?/token$")


class TokenCacheMiddleware:
    """Answer a token request with the cache headers the RFC requires."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Add `Cache-Control` and `Pragma` to a token endpoint's answer."""
        path = scope.get("path", "") if scope["type"] == "http" else ""
        if not _TOKEN_PATH.search(path):
            await self.app(scope, receive, send)
            return

        async def send_with_no_store(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["cache-control"] = "no-store"
                headers["pragma"] = "no-cache"
            await send(message)

        await self.app(scope, receive, send_with_no_store)
