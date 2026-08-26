"""Order Splunk collection entries the way splunkd orders them.

Every ``/services`` collection takes ``sort_key`` and ``sort_dir``, and
splunkd sorts by ``name`` ascending when neither is given — so a client that
sends nothing still gets a stable, alphabetical page, and one that pages
through a collection sees each record once. mockdr answered in whatever
order its store held, and ignored both parameters while declaring them:
``sort_dir=desc`` came back identical to ``sort_dir=asc``.

``sort_key`` names either the entry itself (``name``) or one of its content
fields (``totalEventCount``). ``sort_mode`` says how to compare: ``auto``,
the default, reads a value as a number where it is one and as text
otherwise; ``num`` reads it as a number; ``alpha`` and ``alpha_case`` read
it as text, so ``97716, 5907, 4483, 31270`` is a descending *alpha* sort of
those event counts and only ``31270`` is out of numeric place. A key nothing
carries is not an error — splunkd answers 200 and leaves the order alone.

Measured on 10.4.2, except the difference between ``alpha`` and
``alpha_case``: this install has no two names differing only in case, so
that pair follows Splunk's documented meaning — ``alpha`` ignores case and
``alpha_case`` does not — rather than a measurement.

This runs *inside* the paging middleware, so the collection is ordered
before it is sliced; sorting a page would order each page separately and
leave the collection as a whole unordered.

Pure ASGI: a request outside ``/splunk/services`` is passed straight through.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from urllib.parse import parse_qs

from starlette.types import ASGIApp, Receive, Scope, Send

from api.middleware.json_rewrite import rewrite_json_body

_SPLUNK_PREFIX = "/splunk/services"
#: What splunkd sorts by when the request says nothing.
_DEFAULT_KEY = "name"


class SplunkSortMiddleware:
    """Sort Atom ``entry`` lists per ``sort_key``/``sort_dir``."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Order a Splunk collection response."""
        if scope["type"] != "http" or not scope.get("path", "").startswith(_SPLUNK_PREFIX):
            await self.app(scope, receive, send)
            return

        query = parse_qs(scope.get("query_string", b"").decode("latin-1"))
        key = _first(query, "sort_key") or _DEFAULT_KEY
        descending = (_first(query, "sort_dir") or "asc").lower() == "desc"
        mode = (_first(query, "sort_mode") or "auto").lower()

        def rewrite(payload: object) -> tuple[bytes, str] | None:
            if not isinstance(payload, dict) or not isinstance(payload.get("entry"), list):
                return None
            entries = payload["entry"]
            if len(entries) < 2 or not _sortable(entries, key):
                return None
            entries.sort(key=_key(key, mode), reverse=descending)
            return json.dumps(payload).encode(), "application/json"

        await rewrite_json_body(
            self.app, scope, receive, send,
            claims=lambda status, headers: True,  # noqa: ARG005 - every JSON body here
            rewrite=rewrite,
        )


def _first(query: dict[str, list[str]], name: str) -> str | None:
    values = query.get(name)
    return values[0] if values else None


def _value(entry: object, key: str) -> object:
    if not isinstance(entry, dict):
        return None
    if key in entry:
        return entry[key]
    content = entry.get("content")
    return content.get(key) if isinstance(content, dict) else None


def _sortable(entries: list, key: str) -> bool:
    """Whether any entry carries the key at all.

    splunkd leaves the order alone for a key nothing has, rather than
    erroring — and so must this, or a client's typo would silently reorder
    the collection by nothing.
    """
    return any(_value(entry, key) is not None for entry in entries)


def _key(key: str, mode: str = "auto") -> Callable[[object], tuple[int, float, str]]:
    numeric = mode in ("auto", "num")
    fold = mode != "alpha_case"

    def sort_key(entry: object) -> tuple[int, float, str]:
        value = _value(entry, key)
        if value is None:
            return (2, 0.0, "")
        if numeric:
            if isinstance(value, bool):
                return (0, float(value), "")
            if isinstance(value, (int, float)):
                return (0, float(value), "")
            try:
                return (0, float(str(value)), "")
            except ValueError:
                pass
        text = str(value)
        return (1, 0.0, text.lower() if fold else text)
    return sort_key
