"""Cortex XDR XQL API router.

All endpoints use POST with ``{"request_data": {...}}`` body wrapper.
Responses use ``{"reply": {...}}`` envelope via ``build_xdr_*`` helpers.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Response

from api.xdr_auth import require_xdr_auth
from application.xdr_xql import queries as xql_queries
from utils.xdr_fixtures import xdr_shape
from utils.xdr_response import XDR_ERR_INTERNAL, build_xdr_error, require_request_data

router = APIRouter(tags=["XDR XQL"])


def _bad_request(extra: str) -> HTTPException:
    """A request the client got wrong, in the XDR error envelope."""
    return HTTPException(status_code=400, detail=build_xdr_error(400, "Bad Request", extra))


@router.post("/xql/start_xql_query")
@xdr_shape("xql_start_xql_query")
def start_xql_query(
    body: dict = Body(...),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Start an XQL query execution."""
    request_data = require_request_data(body)
    query_string = request_data.get("query")
    # `query` is the one member the route requires; an empty one is no query.
    if not isinstance(query_string, str) or not query_string.strip():
        raise _bad_request("query is required and must be a non-empty string")
    return xql_queries.start_query(query_string)


@router.post("/xql/get_query_results")
@xdr_shape("xql_get_query_results")
def get_query_results(
    body: dict = Body(...),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Get results for an XQL query."""
    request_data = require_request_data(body)
    query_id = request_data.get("query_id")
    # A list or object here used to reach the store as a key and answer 500
    # (unhashable type); it is a malformed request.
    if not isinstance(query_id, str) or not query_id:
        raise _bad_request("query_id is required and must be a string")
    pending_flag = request_data.get("pending_flag", True)
    if not isinstance(pending_flag, bool):
        raise _bad_request("pending_flag must be a boolean")
    limit = request_data.get("limit")
    if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit < 0):
        raise _bad_request("limit must be a non-negative integer")
    result = xql_queries.get_query_results(query_id, pending_flag=pending_flag, limit=limit)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, XDR_ERR_INTERNAL, f"Query {query_id} not found"),
        )
    return result


@router.post("/xql/get_query_results_stream")
def get_query_results_stream(
    body: dict = Body(...),
    _: object = Depends(require_xdr_auth),
) -> Response:
    """Stream the results of a query too large to answer inline."""
    request_data = require_request_data(body)
    stream_id = request_data.get("stream_id")
    if not isinstance(stream_id, str) or not stream_id:
        raise _bad_request("stream_id is required and must be a string")
    gzip_compressed = request_data.get("is_gzip_compressed", False)
    if not isinstance(gzip_compressed, bool):
        raise _bad_request("is_gzip_compressed must be a boolean")
    data = xql_queries.get_query_results_stream(stream_id, gzip_compressed=gzip_compressed)
    if data is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, XDR_ERR_INTERNAL, f"Stream {stream_id} not found"),
        )
    return Response(content=data, media_type="application/octet-stream")


@router.post("/xql/get_quota")
@xdr_shape("xql_get_quota")
def get_quota(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Get XQL query quota information."""
    return xql_queries.get_quota()
