"""Apply ``count`` and ``offset`` to Splunk Atom collection responses.

Every ``/services`` collection endpoint accepts ``count`` and ``offset``, and
splunklib's ``Collection.list()`` sends them. mockdr declared them on no route,
so both were dropped and the full collection came back with a ``paging`` block
that contradicted it — ``perPage: 30`` alongside 48 entries.

Doing this centrally keeps every collection consistent, which is how splunkd
behaves: the paging rules belong to the Atom envelope, not to each endpoint.

Pure ASGI: a request outside ``/splunk/services``, or one that names neither
parameter, is passed straight through.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs

from starlette.types import ASGIApp, Receive, Scope, Send

from api.middleware.json_rewrite import rewrite_json_body

_SPLUNK_PREFIX = "/splunk/services"
_DEFAULT_COUNT = 30
#: What splunkd reports as the page size for `count=0`, which means "all":
#: its own maximum, not the number of entries that happened to come back
#: (measured on 10.4.2 — the same 10000000 whether the collection holds
#: fourteen entries or none).
_UNLIMITED_PER_PAGE = 10000000


class SplunkPagingMiddleware:
    """Slice Atom ``entry`` lists per the request's ``count``/``offset``."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Apply paging to a Splunk collection response."""
        if scope["type"] != "http" or not scope.get("path", "").startswith(_SPLUNK_PREFIX):
            await self.app(scope, receive, send)
            return

        query = parse_qs(scope.get("query_string", b"").decode("latin-1"))
        if "count" not in query and "offset" not in query:
            await self.app(scope, receive, send)
            return

        offset = max(_as_int(_first(query, "offset"), 0), 0)
        # Splunk documents count=0 as "all entries", and splunklib encodes it as
        # `null_count = 0`; treating it as a limit returned nothing.
        count = _as_int(_first(query, "count"), _DEFAULT_COUNT)

        def rewrite(payload: object) -> tuple[bytes, str] | None:
            if not isinstance(payload, dict) or not isinstance(payload.get("entry"), list):
                return None
            _apply_paging(payload, offset, count)
            return json.dumps(payload).encode(), "application/json"

        await rewrite_json_body(
            self.app, scope, receive, send,
            claims=lambda status, headers: True,  # noqa: ARG005 - every JSON body here
            rewrite=rewrite,
        )


def _first(query: dict[str, list[str]], name: str) -> str | None:
    values = query.get(name)
    return values[0] if values else None


def _as_int(value: str | None, default: int) -> int:
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def _apply_paging(payload: dict, offset: int, count: int) -> None:
    """Slice ``entry`` in place and make ``paging`` describe the result."""
    entries = payload["entry"]
    total = len(entries)

    windowed = entries[offset:]
    if count > 0:
        windowed = windowed[:count]

    payload["entry"] = windowed
    paging = payload.get("paging")
    if isinstance(paging, dict):
        paging["total"] = paging.get("total", total)
        paging["offset"] = offset
        paging["perPage"] = count if count > 0 else _UNLIMITED_PER_PAGE
