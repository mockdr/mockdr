"""SentinelOne's ``countOnly``: the total, without the objects.

The 2.1 swagger documents ``countOnly`` on 120 list operations — every list
route this mock serves — as "If true, only total number of items will be
returned, without any of the actual objects." No route read it, so a client
asking how many threats match, to decide whether to page at all, was sent
the first page of them as well; one that asks with ``limit=1000`` to get
the count cheaply fetched a thousand records it threw away.

The routes build their answer as usual and this empties it on the way out:
``data`` becomes an empty list (``data.sites`` on ``/sites``, whose
``allSites`` summary is a count and stays), ``pagination.totalItems`` is
kept, and ``nextCursor`` is null — there are no objects to continue from.
Only an answer that is a list page — one with a ``pagination.totalItems`` —
is touched, so a route without a total is left alone.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs

from starlette.types import ASGIApp, Receive, Scope, Send

from api.middleware.json_rewrite import rewrite_json_body

_PREFIX = "/web/api/v2.1/"
_TRUE = ("true", "1")


def _asks_for_count_only(scope: Scope) -> bool:
    """Whether this is a SentinelOne GET carrying ``countOnly=true``."""
    if scope["type"] != "http" or scope.get("method") != "GET":
        return False
    if not str(scope.get("path", "")).startswith(_PREFIX):
        return False
    query = parse_qs(scope.get("query_string", b"").decode("latin-1"))
    return any(v.strip().lower() in _TRUE for v in query.get("countOnly", []))


def _counted(payload: object) -> tuple[bytes, str] | None:
    """The page with its objects removed, or None if it is not a list page."""
    if not isinstance(payload, dict):
        return None
    pagination = payload.get("pagination")
    if not isinstance(pagination, dict) or "totalItems" not in pagination:
        return None
    data = payload.get("data")
    if isinstance(data, list):
        payload["data"] = []
    elif isinstance(data, dict) and isinstance(data.get("sites"), list):
        payload["data"] = {**data, "sites": []}
    else:
        return None
    payload["pagination"] = {**pagination, "nextCursor": None}
    return json.dumps(payload, separators=(",", ":")).encode(), "application/json"


class CountOnlyMiddleware:
    """Answer ``countOnly=true`` with the total and no objects."""

    def __init__(self, app: ASGIApp) -> None:
        """Wrap the given ASGI application."""
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Pass everything through, emptying a list page that asked for its count."""
        if not _asks_for_count_only(scope):
            await self.app(scope, receive, send)
            return
        await rewrite_json_body(
            self.app, scope, receive, send,
            claims=lambda status, _headers: status == 200,
            rewrite=_counted,
        )
