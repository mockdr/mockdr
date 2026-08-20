"""Apply ``count`` and ``offset`` to Splunk Atom collection responses.

Every ``/services`` collection endpoint accepts ``count`` and ``offset``, and
splunklib's ``Collection.list()`` sends them. mockdr declared them on no route,
so both were dropped and the full collection came back with a ``paging`` block
that contradicted it — ``perPage: 30`` alongside 48 entries.

Doing this centrally keeps every collection consistent, which is how splunkd
behaves: the paging rules belong to the Atom envelope, not to each endpoint.
"""
from __future__ import annotations

import json

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

_SPLUNK_PREFIX = "/splunk/services"
_DEFAULT_COUNT = 30


class SplunkPagingMiddleware(BaseHTTPMiddleware):
    """Slice Atom ``entry`` lists per the request's ``count``/``offset``."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint,
    ) -> Response:
        """Apply paging to a Splunk collection response."""
        response = await call_next(request)

        if not request.url.path.startswith(_SPLUNK_PREFIX):
            return response
        if not response.headers.get("content-type", "").startswith("application/json"):
            return response
        if "count" not in request.query_params and "offset" not in request.query_params:
            return response

        body_iterator = getattr(response, "body_iterator", None)
        if body_iterator is None:
            return response
        raw = b"".join([chunk async for chunk in body_iterator])

        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return Response(
                content=raw,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type,
            )

        if not isinstance(payload, dict) or "entry" not in payload:
            return Response(
                content=raw,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type,
            )

        _apply_paging(payload, request)
        return JSONResponse(
            content=payload,
            status_code=response.status_code,
            headers={
                k: v for k, v in response.headers.items()
                if k.lower() not in ("content-length", "content-type")
            },
        )


def _as_int(value: str | None, default: int) -> int:
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def _apply_paging(payload: dict, request: Request) -> None:
    """Slice ``entry`` in place and make ``paging`` describe the result."""
    entries = payload.get("entry")
    if not isinstance(entries, list):
        return

    total = len(entries)
    offset = max(_as_int(request.query_params.get("offset"), 0), 0)
    # Splunk documents count=0 as "all entries", and splunklib encodes it as
    # `null_count = 0`; treating it as a limit returned nothing.
    count = _as_int(request.query_params.get("count"), _DEFAULT_COUNT)

    windowed = entries[offset:]
    if count > 0:
        windowed = windowed[:count]

    payload["entry"] = windowed
    paging = payload.get("paging")
    if isinstance(paging, dict):
        paging["total"] = paging.get("total", total)
        paging["offset"] = offset
        paging["perPage"] = count if count > 0 else total
