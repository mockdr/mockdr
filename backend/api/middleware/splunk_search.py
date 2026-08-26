"""Narrow a Splunk collection with its ``search`` parameter.

Every ``/services`` collection takes ``search``, and splunkd reads it two
ways (measured on 10.4.2):

* ``search=name=main`` — an exact match on one field, whether the field sits
  on the entry or in its ``content``;
* ``search=main`` — a bare term, matched as a substring against the entry's
  own fields *and* every value in its content. It is broader than it looks:
  `search=main` matches every index, because each one carries
  ``defaultDatabase: main``.

A term nothing matches answers an empty collection, not the whole of it.
mockdr declared the parameter and ignored it, so a client narrowing a
collection was handed all of it with a 200 — and, worse, a ``paging.total``
that agreed with the answer rather than with the question.

This runs inside the sorting and paging middlewares, so what is sorted and
sliced — and counted — is what the search selected.

Pure ASGI: a request outside ``/splunk/services``, or one without ``search``,
is passed straight through.
"""

from __future__ import annotations

from urllib.parse import parse_qs

from starlette.types import ASGIApp, Receive, Scope, Send

from api.middleware.json_rewrite import rewrite_json_body
from utils.splunk_json import splunk_json

_SPLUNK_PREFIX = "/splunk/services"
#: `search` means the search *string* here, not a collection filter.
_NOT_A_FILTER = ("/splunk/services/search/jobs", "/splunk/services/search/v2/jobs",
                 "/splunk/services/search/parser", "/splunk/services/search/v2/parser")


class SplunkSearchMiddleware:
    """Keep the entries a collection's ``search`` selects."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Filter a Splunk collection response."""
        path = scope.get("path", "")
        if (scope["type"] != "http" or not path.startswith(_SPLUNK_PREFIX)
                or path.startswith(_NOT_A_FILTER)):
            await self.app(scope, receive, send)
            return

        terms = parse_qs(scope.get("query_string", b"").decode("latin-1")).get("search")
        if not terms:
            await self.app(scope, receive, send)
            return

        def rewrite(payload: object) -> tuple[bytes, str] | None:
            if not isinstance(payload, dict) or not isinstance(payload.get("entry"), list):
                return None
            kept = [
                entry for entry in payload["entry"]
                if all(_matches(entry, term) for term in terms)
            ]
            payload["entry"] = kept
            # The population changed, so the count of it has to. splunkd
            # answers `total: 0` for a term nothing matches; leaving the
            # unfiltered total there would tell a client its filter had
            # found nothing *of many*, which is a different statement.
            paging = payload.get("paging")
            if isinstance(paging, dict):
                paging["total"] = len(kept)
            return splunk_json(payload), "application/json"

        await rewrite_json_body(
            self.app, scope, receive, send,
            claims=lambda status, headers: True,  # noqa: ARG005 - every JSON body here
            rewrite=rewrite,
        )


def _fields(entry: object) -> dict:
    """An entry's own fields and its content, in one mapping."""
    if not isinstance(entry, dict):
        return {}
    content = entry.get("content")
    return {
        **{k: v for k, v in entry.items() if not isinstance(v, (dict, list))},
        **(content if isinstance(content, dict) else {}),
    }


def _matches(entry: object, term: str) -> bool:
    """Whether one entry satisfies one search term."""
    fields = _fields(entry)
    key, sep, value = term.partition("=")
    if sep and key and not key.startswith("_"):
        held = fields.get(key)
        if held is None:
            return False
        return str(held).lower() == value.lower() or _as_bool(held, value)
    needle = term.lower()
    return any(needle in str(v).lower() for v in fields.values() if v is not None)


def _as_bool(held: object, value: str) -> bool:
    """`disabled=1` matches the boolean `True`, which is how splunkd reads it."""
    if not isinstance(held, bool):
        return False
    return (value.strip().lower() in ("1", "true", "t", "yes", "on")) is held
