"""The three things Elasticsearch lets a client do to any answer.

They are not per-route features — every endpoint takes them — and mockdr
took all three as decoration:

* **`?filter_path=`** keeps only the paths named, with `*` for one segment,
  `**` for any depth, and a leading `-` to drop instead of keep. A client
  asking for `hits.hits._source` was handed the whole document tree, which
  is more data than it asked for and a shape it did not expect. Nothing
  matching answers `{}`.
* **`?pretty`** indents two spaces, separates with ` : ` and ends with a
  newline, which is Jackson's own printer. A client that logs or diffs the
  answer sees a different document.
* **`X-Opaque-Id`** is echoed back on the response. The official clients
  offer it as `opaque_id` precisely so a request can be found again in a
  log, and mockdr dropped it.

All measured on 8.15. `?format=yaml` and `Accept: application/yaml` are the
one member of this family left alone: Elasticsearch answers those in YAML,
and rendering YAML the way Jackson renders it is a larger piece of work than
the clients that would ask for it justify — a client asking for YAML gets
JSON here, which is stated rather than hidden.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qs

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_ES_PREFIX = "/elastic"
_JSON = "application/json"

#: Jackson's pretty printer, to the character.
_PRETTY = {"indent": 2, "separators": (",", " : ")}


class ElasticShapingMiddleware:
    """Apply `filter_path`, `pretty` and `X-Opaque-Id` to an answer."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Shape a JSON answer the way this request asked for it."""
        path = scope.get("path", "") if scope["type"] == "http" else ""
        if not path.startswith(_ES_PREFIX):
            await self.app(scope, receive, send)
            return

        # `?pretty` carries no value, and a blank value is dropped by default.
        query = parse_qs(
            bytes(scope.get("query_string", b"")).decode("latin-1"),
            keep_blank_values=True,
        )
        wanted = ",".join(query.get("filter_path", []))
        pretty = _asked_for(query, "pretty")
        opaque = _request_header(scope, b"x-opaque-id")
        if not (wanted or pretty or opaque):
            await self.app(scope, receive, send)
            return

        start: Message | None = None
        body = b""

        async def collect(message: Message) -> None:
            nonlocal start, body
            if message["type"] == "http.response.start":
                start = message
                if opaque:
                    MutableHeaders(scope=message)["x-opaque-id"] = opaque
                if not (wanted or pretty):
                    await send(message)
                return
            if message["type"] != "http.response.body":
                await send(message)
                return
            if not (wanted or pretty):
                await send(message)
                return
            body += message.get("body", b"")
            if message.get("more_body"):
                return
            await _send_shaped(send, start, body, wanted, pretty=pretty)

        await self.app(scope, receive, collect)


def _asked_for(query: dict[str, list[str]], name: str) -> bool:
    """Whether a flag parameter is on — `?pretty` and `?pretty=true` both are."""
    values = query.get(name)
    if values is None:
        return False
    return values[0].lower() not in ("false", "0", "no")


def _request_header(scope: Scope, wanted: bytes) -> str:
    """One request header, or the empty string."""
    for name, value in scope.get("headers", []):
        if name == wanted:
            return str(bytes(value).decode("latin-1"))
    return ""


async def _send_shaped(
    send: Send,
    start: Message | None,
    body: bytes,
    wanted: str,
    *,
    pretty: bool,
) -> None:
    """Filter and re-render the answer, or pass it through untouched."""
    if start is None:
        return
    headers = MutableHeaders(scope=start)
    if not headers.get("content-type", "").startswith(_JSON):
        # `_cat` answers text and `_bulk` takes NDJSON; neither is shaped.
        await send(start)
        await send({"type": "http.response.body", "body": body})
        return
    try:
        document = json.loads(body)
    except ValueError:
        await send(start)
        await send({"type": "http.response.body", "body": body})
        return

    if wanted:
        document = filter_path(document, wanted)
    rendered = (
        # Jackson ends a pretty document with a newline; a compact one has
        # none.
        (json.dumps(document, **_PRETTY) + "\n").encode()  # type: ignore[arg-type]
        if pretty else
        json.dumps(document, separators=(",", ":")).encode()
    )
    headers["content-length"] = str(len(rendered))
    await send(start)
    await send({"type": "http.response.body", "body": rendered})


def filter_path(document: Any, spec: str) -> Any:  # noqa: ANN401 - any JSON
    """Keep only the paths named, or drop the ones marked with a leading `-`.

    Args:
        document: The parsed answer.
        spec:     The comma-separated `filter_path` value.

    Returns:
        The document with only what was asked for, or `{}` when nothing in it
        matched — which is what Elasticsearch answers.
    """
    keeps = [p for p in spec.split(",") if p and not p.startswith("-")]
    drops = [p[1:] for p in spec.split(",") if p.startswith("-")]
    result = document
    if keeps:
        result = _keep(result, [_pattern(p) for p in keeps])
    for path in drops:
        result = _drop(result, _pattern(path))
    return result if result is not None else {}


def _pattern(path: str) -> list[str]:
    """One filter path, split into the segments it matches."""
    return path.split(".")


def _matches(segment: str, name: str) -> bool:
    """Whether one path segment matches a member name."""
    if segment in ("*", "**"):
        return True
    if "*" in segment:
        return re.fullmatch(segment.replace("*", "[^.]*"), name) is not None
    return segment == name


def _keep(node: Any, patterns: list[list[str]]) -> Any:  # noqa: ANN401
    """The parts of *node* any of these patterns reaches."""
    if isinstance(node, list):
        kept = [_keep(item, patterns) for item in node]
        remaining = [item for item in kept if item not in (None, {}, [])]
        return remaining or None
    if not isinstance(node, dict):
        return node

    out: dict[str, Any] = {}
    for name, value in node.items():
        deeper: list[list[str]] = []
        for pattern in patterns:
            if not pattern or not _matches(pattern[0], name):
                if pattern and pattern[0] == "**":
                    deeper.append(pattern)
                continue
            if len(pattern) == 1:
                out[name] = value
                break
            deeper.append(pattern[1:] if pattern[0] != "**" else pattern)
        else:
            if deeper:
                below = _keep(value, deeper)
                if below not in (None, {}, []):
                    out[name] = below
    return out or None


def _drop(node: Any, pattern: list[str]) -> Any:  # noqa: ANN401
    """*node* without the part this pattern reaches."""
    if isinstance(node, list):
        return [_drop(item, pattern) for item in node]
    if not isinstance(node, dict) or not pattern:
        return node
    out = {}
    for name, value in node.items():
        if _matches(pattern[0], name):
            if len(pattern) == 1:
                continue
            out[name] = _drop(value, pattern[1:])
        else:
            out[name] = value
    return out
