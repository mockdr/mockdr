"""Apply Splunk's ``f`` parameter to the content of Atom entries.

Every ``/services`` endpoint takes ``f``, repeated once per field, and answers
with only those content keys — ``eai:acl`` always beside them, whether it was
asked for or not. Wildcards work: ``f=max*`` selects the eighteen ``max…``
settings of an index. A name that matches nothing leaves the content with
``eai:acl`` alone rather than erroring.

mockdr declared ``f`` on no route and answered with all 113 content keys of an
index whatever was asked for. A client narrowing a large collection got the
whole of it, which costs it nothing but tells it nothing either — and a client
that reads ``content`` as "the fields I asked for" reads the wrong ones.

Measured against Splunk 10.4.2. Pure ASGI: a request outside
``/splunk/services``, or one without ``f``, is passed straight through.
"""

from __future__ import annotations

import fnmatch
import json
from urllib.parse import parse_qs

from starlette.types import ASGIApp, Receive, Scope, Send

from api.middleware.json_rewrite import rewrite_json_body

_SPLUNK_PREFIX = "/splunk/services"
#: Present in a filtered entry's content whether or not it was selected.
_ALWAYS = "eai:acl"


class SplunkFieldFilterMiddleware:
    """Narrow each entry's ``content`` to the fields ``f`` names."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Apply the field filter to a Splunk response."""
        if scope["type"] != "http" or not scope.get("path", "").startswith(_SPLUNK_PREFIX):
            await self.app(scope, receive, send)
            return

        patterns = parse_qs(scope.get("query_string", b"").decode("latin-1")).get("f")
        if not patterns:
            await self.app(scope, receive, send)
            return

        def rewrite(payload: object) -> tuple[bytes, str] | None:
            if not isinstance(payload, dict) or not isinstance(payload.get("entry"), list):
                return None
            for entry in payload["entry"]:
                content = entry.get("content") if isinstance(entry, dict) else None
                if isinstance(content, dict):
                    entry["content"] = _select(content, patterns)
            return json.dumps(payload).encode(), "application/json"

        await rewrite_json_body(
            self.app, scope, receive, send,
            claims=lambda status, headers: True,  # noqa: ARG005 - every JSON body here
            rewrite=rewrite,
        )


def _select(content: dict, patterns: list[str]) -> dict:
    """The content keys any pattern names, with ``eai:acl`` beside them."""
    kept = {
        key: value for key, value in content.items()
        if any(fnmatch.fnmatchcase(key, pattern) for pattern in patterns)
    }
    kept[_ALWAYS] = content.get(_ALWAYS)
    return kept
