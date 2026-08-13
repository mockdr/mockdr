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


class SplunkOutputModeMiddleware(BaseHTTPMiddleware):
    """Render Splunk responses as XML unless ``output_mode=json`` was given."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint,
    ) -> Response:
        """Convert a JSON Splunk response body to Atom XML when appropriate."""
        response = await call_next(request)

        path = request.url.path
        if not path.startswith(_SPLUNK_PREFIX) or path.startswith(_HEC_PREFIX):
            return response
        if request.query_params.get("output_mode", "").lower() == "json":
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
