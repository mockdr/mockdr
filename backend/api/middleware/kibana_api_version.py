"""Kibana's `elastic-api-version` on the operations that carry one.

8.15 registers some routes through its *versioned* router and the rest
plainly, and only the versioned ones answer with
`elastic-api-version: 2023-10-31`.  It is a property of the operation, not
of the path or the family: `GET /api/exception_lists/_find` carries one and
`GET /api/exception_lists/items/_find` does not; `GET /api/endpoint/action`
does and `GET /api/endpoint/action_status` does not.  The header survives
that operation's own errors — a handler's 400 carries it — but a refusal
raised *before* dispatch does not, which is why an unknown query member is a
400 with no version on a versioned route.

Measured operation by operation on 8.15 against every route mockdr serves.
Only `GET` is listed: measuring a write means letting it succeed, since
neither a query-schema nor a body-schema refusal carries the header, and
that would mean creating objects on the probe instance.  The 34 write
operations are therefore unmeasured rather than known to carry none.
"""
from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send

#: The version every versioned route answers with; only one is in use.
_VERSION = b"2023-10-31"

#: The `GET` operations measured to carry it, by mockdr's own route paths.
_VERSIONED_GETS: frozenset[str] = frozenset({
    "/api/data_views",
    "/api/detection_engine/index",
    "/api/detection_engine/privileges",
    "/api/detection_engine/rules",
    "/api/detection_engine/rules/_find",
    "/api/detection_engine/rules/prepackaged/_status",
    "/api/detection_engine/tags",
    "/api/endpoint/action",
    "/api/endpoint/action/{action_id}",
    "/api/endpoint/metadata",
    "/api/endpoint/metadata/{agent_id}",
    "/api/exception_lists",
    "/api/exception_lists/_find",
    "/api/exception_lists/items",
    "/api/exception_lists/summary",
    "/api/fleet/agent_policies",
    "/api/fleet/agents",
    "/api/fleet/agents/setup",
    "/api/lists/_find",
    "/api/note",
    "/api/osquery/packs",
    "/api/timeline",
    "/api/timelines",
})


class KibanaApiVersionMiddleware:
    """Answer with `elastic-api-version` where 8.15 answers with one."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") != "GET":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if not path.startswith("/kibana"):
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                route = scope.get("route")
                template = getattr(route, "path", None)
                # A refusal raised before the handler runs carries no version,
                # even on a versioned route — the header comes from dispatch.
                refused = scope.get("kbn_refused_before_dispatch", False)
                if template in _VERSIONED_GETS and not refused:
                    headers = message.setdefault("headers", [])
                    if not any(n.lower() == b"elastic-api-version" for n, _ in headers):
                        headers.append((b"elastic-api-version", _VERSION))
            await send(message)

        await self.app(scope, receive, send_wrapper)
