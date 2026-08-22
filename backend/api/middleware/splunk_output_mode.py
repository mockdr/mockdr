"""Middleware honouring Splunk's ``output_mode`` query parameter.

splunkd serves Atom XML by default and JSON only on request. The routers build
JSON — the SDKs ask for it, and it is far easier to work with — so this
middleware renders that body as XML whenever the caller did *not* ask for JSON,
which is what the real server would have done.

HEC (``/services/collector``) is exempt: it is a separate service that always
answers in JSON and ignores ``output_mode``.
"""
from __future__ import annotations

import json

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from utils.splunk.xml_output import render_splunk_xml

_SPLUNK_PREFIX = "/splunk"
_HEC_PREFIX = "/splunk/services/collector"
# The KV Store *data* API is JSON-only in real Splunk — output_mode does not
# apply to it. splunklib proves it: KVStoreCollectionData.query() calls
# json.loads on the body and never sends output_mode. Rendering Atom XML
# here broke every SDK KV Store call unconditionally.
_KVSTORE_DATA_MARKER = "/storage/collections/data/"


async def _asked_for_json(request: Request) -> bool:
    """Whether the caller asked for JSON, in the query or in a form body.

    splunkd honours ``output_mode`` in either place, and splunklib relies on
    the second: its ``post()`` puts every parameter, ``output_mode`` included,
    into the form body. Reading only the query string rendered every SDK
    POST that lacked a query parameter as Atom XML — which the harness
    surfaced the moment a probe sent the parameter the way splunklib does.
    """
    if request.query_params.get("output_mode", "").lower() == "json":
        return True
    content_type = request.headers.get("content-type", "")
    if request.method == "POST" and content_type.startswith("application/x-www-form-urlencoded"):
        # body() first: it is what Starlette caches and replays to the route.
        # form() alone streams straight from the socket, and the route then
        # finds an empty form — every Splunk form POST broke at once.
        await request.body()
        form = await request.form()
        return str(form.get("output_mode", "")).lower() == "json"
    return False


class SplunkOutputModeMiddleware(BaseHTTPMiddleware):
    """Render Splunk responses as XML unless ``output_mode=json`` was given."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint,
    ) -> Response:
        """Convert a JSON Splunk response body to Atom XML when appropriate."""
        path = request.url.path
        splunk = path.startswith(_SPLUNK_PREFIX) and not path.startswith(_HEC_PREFIX)
        # Read before the route runs: Starlette replays a body the middleware
        # has consumed, so the route still sees its form. Only for a Splunk
        # form POST — anything else is left untouched.
        wants_json = splunk and await _asked_for_json(request)

        response = await call_next(request)

        if not splunk:
            return response
        if _KVSTORE_DATA_MARKER in path:
            return response
        if wants_json:
            return response
        if not response.headers.get("content-type", "").startswith("application/json"):
            return response
        # Responses from call_next stream their body; anything else (a plain
        # Response returned by an outer middleware) is passed through as-is.
        body_iterator = getattr(response, "body_iterator", None)
        if body_iterator is None:
            return response

        chunks = [chunk async for chunk in body_iterator]
        body = b"".join(
            chunk.encode() if isinstance(chunk, str) else bytes(chunk) for chunk in chunks
        )
        try:
            payload = json.loads(body)
        except ValueError:
            return Response(
                content=body,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type,
            )

        xml = render_splunk_xml(payload)
        headers = dict(response.headers)
        headers.pop("content-length", None)
        headers.pop("content-type", None)
        return Response(
            content=xml,
            status_code=response.status_code,
            headers=headers,
            media_type="text/xml; charset=UTF-8",
        )
