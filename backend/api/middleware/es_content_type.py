"""Elasticsearch refuses a body sent under a content type it does not read.

8.15 answers `406` — not the `415` one would guess — with the bare-string
error shape it uses for the 405 too:

    {"error": "Content-Type header [text/plain] is not supported",
     "status": 406}

It reads six types, and the check is only made when there *is* a body: a GET
with none, or a POST with an empty one, is served whatever the header says.
mockdr read every body as JSON and answered a `parsing_exception` instead —
a 400 about the content where the product refuses the header, which sends a
client that forgot `Content-Type` looking at its query.

Deliberately not imitated: the cluster answers *in* the format asked for —
`application/yaml` comes back as YAML and `application/cbor` as CBOR — so
those types are accepted here, their bodies read as JSON, and the answer is
JSON whatever was asked.  Refusing them instead would invent a 406 the
cluster never gives, which is the worse of the two.  A body that really is
YAML, CBOR or SMILE is therefore not parsed; only the header is honoured.

Measured on 8.15, type by type.
"""
from __future__ import annotations

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

#: What the cluster reads a body as.  `application/json` covers a charset
#: and any casing; `vnd.elasticsearch+json` is what its own clients send.
_READABLE = frozenset({
    "application/json",
    "application/yaml",
    "application/cbor",
    "application/smile",
    "application/x-ndjson",
    "application/vnd.elasticsearch+json",
})


def _base_type(value: str) -> str:
    """The media type alone, lower-cased: no charset, no compatibility hint."""
    return value.split(";", 1)[0].strip().lower()


class ElasticContentTypeMiddleware:
    """Refuse a body under a content type Elasticsearch does not read."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope.get("path", "").startswith("/elastic"):
            await self.app(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        content_type = headers.get("content-type", "")
        base = _base_type(content_type)
        if base in _READABLE:
            if base != "application/json":
                # Read as JSON downstream, since the answer is JSON either
                # way; the header alone must not turn a body the cluster
                # accepts into a parse error.
                scope = {**scope, "headers": [
                    (name, b"application/json") if name.lower() == b"content-type"
                    else (name, value)
                    for name, value in scope["headers"]
                ]}
            await self.app(scope, receive, send)
            return

        # Only a request that actually carries a body is refused.  Reading it
        # here would consume the stream, so the first message decides and is
        # handed on unchanged.
        first = await receive()
        has_body = bool(first.get("body")) or first.get("more_body", False)
        if not has_body:
            await self.app(scope, _replay(first, receive), send)
            return
        await JSONResponse(
            status_code=406,
            content={
                "error": f"Content-Type header [{content_type}] is not supported",
                "status": 406,
            },
        )(scope, _replay(first, receive), send)


def _replay(first: Message, receive: Receive) -> Receive:
    """Hand back the message already taken, then the rest of the stream."""
    sent = False

    async def replay() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return first
        return await receive()

    return replay
