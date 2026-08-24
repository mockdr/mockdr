"""Middleware honouring Splunk's ``output_mode`` query parameter.

splunkd serves Atom XML by default and JSON only on request. The routers build
JSON — the SDKs ask for it, and it is far easier to work with — so this
middleware renders that body as XML whenever the caller did *not* ask for JSON,
which is what the real server would have done.

HEC (``/services/collector``) is exempt: it is a separate service that always
answers in JSON and ignores ``output_mode``.

Pure ASGI: a request outside ``/splunk`` never reaches the body-collecting
path, and a Splunk request that asked for JSON is passed straight through.
"""

from __future__ import annotations

from urllib.parse import parse_qs

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from api.middleware.json_rewrite import rewrite_json_body
from utils.splunk.xml_output import render_splunk_xml

_SPLUNK_PREFIX = "/splunk"
_HEC_PREFIX = "/splunk/services/collector"
# The KV Store *data* API is JSON-only in real Splunk — output_mode does not
# apply to it. splunklib proves it: KVStoreCollectionData.query() calls
# json.loads on the body and never sends output_mode. Rendering Atom XML
# here broke every SDK KV Store call unconditionally.
_KVSTORE_DATA_MARKER = "/storage/collections/data/"
_FORM_TYPE = b"application/x-www-form-urlencoded"


class SplunkOutputModeMiddleware:
    """Render Splunk responses as XML unless ``output_mode=json`` was given."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Convert a JSON Splunk response body to Atom XML when appropriate."""
        path = scope.get("path", "")
        if (
            scope["type"] != "http"
            or not path.startswith(_SPLUNK_PREFIX)
            or path.startswith(_HEC_PREFIX)
        ):
            await self.app(scope, receive, send)
            return

        query = parse_qs(scope.get("query_string", b"").decode("latin-1"))
        wants_json = _values(query, "output_mode").lower() == "json"
        if not wants_json and _is_form_post(scope):
            # splunklib's post() puts every parameter, output_mode included,
            # into the form body; reading only the query string rendered every
            # SDK form POST as Atom XML. The body is replayed to the route.
            body, receive = await _buffered_body(receive)
            form = parse_qs(body.decode("latin-1"))
            wants_json = _values(form, "output_mode").lower() == "json"

        if wants_json:
            await self.app(scope, receive, send)
            return

        def claims(status: int, _headers: dict[bytes, bytes]) -> bool:
            # Only the KV Store *data* itself is JSON-only. A refusal — no such
            # collection, a query that is not JSON — comes back as Atom XML on
            # splunkd like any other error (measured on 10.4.2).
            return not (_KVSTORE_DATA_MARKER in path and status < 400)

        await rewrite_json_body(
            self.app, scope, receive, send,
            claims=claims,
            rewrite=lambda payload: (
                render_splunk_xml(payload).encode(),
                "text/xml; charset=UTF-8",
            ),
        )


def _values(query: dict[str, list[str]], name: str) -> str:
    values = query.get(name)
    return values[0] if values else ""


def _is_form_post(scope: Scope) -> bool:
    if scope.get("method") != "POST":
        return False
    for name, value in scope.get("headers", []):
        if name.lower() == b"content-type":
            return bool(value.startswith(_FORM_TYPE))
    return False


async def _buffered_body(receive: Receive) -> tuple[bytes, Receive]:
    """Read the request body, and a ``receive`` that replays it to the route."""
    chunks: list[bytes] = []
    more = True
    while more:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        chunks.append(bytes(message.get("body", b"")))
        more = bool(message.get("more_body"))
    body = b"".join(chunks)
    replayed = False

    async def replay() -> Message:
        nonlocal replayed
        if replayed:
            return await receive()
        replayed = True
        return {"type": "http.request", "body": body, "more_body": False}

    return body, replay
