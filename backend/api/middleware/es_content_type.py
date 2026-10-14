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

The vendor types each carry a REST compatibility version, and the cluster
reads it: `compatible-with=7` or `8` is served, anything else is a 400
`media_type_header_exception` before the request reaches a handler.  The
official 8.x clients send `compatible-with=8` on every request, on bulk and
msearch as `application/vnd.elasticsearch+x-ndjson` — which this mock used to
refuse with a 406, so `helpers.bulk` from elasticsearch-py 8.15 could not
write a single document.  See `RestCompatibleVersionHelper` and
`XContentType` at v8.15.0.
"""
from __future__ import annotations

from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

#: What the cluster reads a body as.  `application/json` covers a charset
#: and any casing; the `vnd.elasticsearch+` forms are what its own clients
#: send — every one `XContentType` registers at v8.15.0, `+x-ndjson` among
#: them, which is how elasticsearch-py 8.x sends `_bulk` and `_msearch`.
_READABLE = frozenset({
    "application/json",
    "application/yaml",
    "application/cbor",
    "application/smile",
    "application/x-ndjson",
    "application/vnd.elasticsearch+json",
    "application/vnd.elasticsearch+x-ndjson",
    "application/vnd.elasticsearch+yaml",
    "application/vnd.elasticsearch+cbor",
    "application/vnd.elasticsearch+smile",
})

#: `RestApiVersion.current()` and `minimumSupported()` on an 8.x cluster.
_CURRENT_MAJOR = 8
_MINIMUM_MAJOR = 7


def _base_type(value: str) -> str:
    """The media type alone, lower-cased: no charset, no compatibility hint."""
    return value.split(";", 1)[0].strip().lower()


def _compatible_with(value: str | None) -> int | None:
    """The `compatible-with` a media type asks for, or None for none.

    `ParsedMediaType` ignores a media range (`*/*`, `application/*`), so a
    range carries no version whatever its parameters say.
    """
    if not value or not value.strip():
        return None
    if _is_range(value):
        return None
    elements = value.lower().split(";")
    for element in elements[1:]:
        name, _, version = element.strip().partition("=")
        if name == "compatible-with" and version.isdigit():
            return int(version)
    return None


def _is_range(value: str) -> bool:
    media = value.split(";", 1)[0].strip()
    return media == "*/*" or media.endswith("/*")


def _rendered(value: str | None) -> str:
    """A header as the message prints it: `null` when it parsed to nothing."""
    if not value or not value.strip() or _is_range(value):
        return "null"
    return value


def _version_problem(accept: str | None, content_type: str | None,
                     has_content: bool) -> str | None:
    """Why the cluster refuses this pair of headers, in its own words.

    `RestCompatibleVersionHelper.getCompatibleVersion` at v8.15.0, check for
    check and message for message; an absent header renders as `null`.
    """
    a_version = _compatible_with(accept)
    c_version = _compatible_with(content_type)
    accept = _rendered(accept)
    content_type = _rendered(content_type)
    accept_version = _CURRENT_MAJOR if a_version is None else a_version
    content_version = _CURRENT_MAJOR if c_version is None else c_version
    if not _MINIMUM_MAJOR <= accept_version <= _CURRENT_MAJOR:
        return (f"Accept version must be either version {_CURRENT_MAJOR} or "
                f"{_MINIMUM_MAJOR}, but found {accept_version}. Accept={accept}")
    if not has_content:
        return None
    if not _MINIMUM_MAJOR <= content_version <= _CURRENT_MAJOR:
        return (f"Content-Type version must be either version {_CURRENT_MAJOR} or "
                f"{_MINIMUM_MAJOR}, but found {content_version}. "
                f"Content-Type={content_type}")
    if content_version != accept_version:
        return ("A compatible version is required on both Content-Type and Accept "
                "headers if either one has requested a compatible version and the "
                f"compatible versions must match. Accept={accept}, "
                f"Content-Type={content_type}")
    if (c_version is None) != (a_version is None):
        return ("A compatible version is required on both Content-Type and Accept "
                "headers if either one has requested a compatible version. "
                f"Accept={accept}, Content-Type={content_type}")
    return None


def _media_type_refusal(cause: str) -> JSONResponse:
    """The 400 a refused compatibility version answers with.

    The outer reason lists the two headers from a `Set.of`, whose order the
    JVM does not fix; `[Content-Type, Accept]` is the order real clusters
    have been seen to print (uken/fluent-plugin-elasticsearch#1061, #1086).
    """
    reason = "Invalid media-type value on headers [Content-Type, Accept]"
    outer = {"type": "media_type_header_exception", "reason": reason}
    return JSONResponse(status_code=400, content={
        "error": {
            "root_cause": [dict(outer)],
            **outer,
            "caused_by": {"type": "status_exception", "reason": cause},
        },
        "status": 400,
    })


async def _authenticates(scope: Scope) -> bool:
    """Whether the request's credentials would pass.

    A refused header is a *bad request*, and the cluster lets an
    authentication failure found before it win: `handleIncomingRequest`
    keeps the inbound exception and only suppresses the media-type one
    (`ExceptionsHelper.useOrSuppress`, AbstractHttpServerTransport at
    v8.15.0).  An anonymous request therefore still gets its 401.
    """
    from api.es_auth import require_es_auth  # noqa: PLC0415 — avoids an import cycle

    request = Request(scope)
    try:
        await require_es_auth(request, request.headers.get("authorization") or "")
    except HTTPException:
        return False
    return True


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

        accept = headers.get("accept")
        if (_compatible_with(accept) is not None
                or _compatible_with(content_type or None) is not None):
            first = await receive()
            receive = _replay(first, receive)
            has_content = bool(first.get("body")) or first.get("more_body", False)
            problem = _version_problem(accept, content_type or None, has_content)
            if problem is not None and await _authenticates(scope):
                await _media_type_refusal(problem)(scope, receive, send)
                return
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
