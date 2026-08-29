"""ASGI middleware that serves ``HEAD`` from the matching ``GET`` route.

RFC 9110 §9.3.2 makes ``HEAD`` mandatory wherever ``GET`` is served, and every
mocked vendor honours it — health checks and link-checkers lean on it. The
routers here register ``GET`` alone, and this FastAPI version does not add the
implicit ``HEAD`` that Starlette's own ``Route`` does, so a ``HEAD`` request
fell through to the unmatched-route fallback and came back ``405``.

Rewriting the method and discarding the body keeps one implementation per
endpoint rather than a second ``HEAD`` handler beside every ``GET``.

Elasticsearch is the exception, and answering HEAD everywhere was wrong
there: it serves HEAD on its *existence* endpoints alone — the root, an
index, a document, an alias — and 405 anywhere else, including
``/_cluster/health`` and ``_search`` (measured on 8.15). A client using HEAD
to ask whether something exists would read a 200 from this mock as a yes on
a path where the cluster does not answer the question at all. Kibana answers
HEAD wherever it answers GET, and is left alone.
"""
from __future__ import annotations

import re

from starlette.types import ASGIApp, Message, Receive, Scope, Send

#: Where Elasticsearch answers HEAD. Anything else under `/elastic` is a 405.
#: `main.py` reads it too, to decide whether HEAD belongs in an `Allow`.
ES_HEAD_PATHS = re.compile(
    r"^/elastic/?$"                                  # the root
    r"|^/elastic/[^_/][^/]*/?$"                      # an index
    r"|^/elastic/[^/]+/_doc/[^/]+/?$"                # a document
    r"|^/elastic/[^/]+/_source/[^/]+/?$"             # a document's source
    r"|^/elastic/_alias/[^/]+/?$"                    # an alias
    r"|^/elastic/[^/]+/_alias/[^/]+/?$",
)


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

        path = scope.get("path", "")
        if path.startswith("/elastic") and not ES_HEAD_PATHS.match(path):
            # Left as HEAD, so the unmatched-route fallback answers the 405
            # Elasticsearch answers — with the `Allow` header it carries.
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
