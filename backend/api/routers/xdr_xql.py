"""Cortex XDR XQL API router.

All endpoints use POST with ``{"request_data": {...}}`` body wrapper.
Responses use ``{"reply": {...}}`` envelope via ``build_xdr_*`` helpers.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException

from api.xdr_auth import require_xdr_auth
from application.xdr_xql import queries as xql_queries
from utils.xdr_response import build_xdr_error

router = APIRouter(tags=["XDR XQL"])


@router.post("/xql/start_xql_query")
def start_xql_query(
    body: dict = Body(...),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Start an XQL query execution."""
    request_data = body.get("request_data", {})
    query_string = request_data.get("query", "")
    return xql_queries.start_query(query_string)


@router.post("/xql/get_query_results")
def get_query_results(
    body: dict = Body(...),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Get results for an XQL query."""
    request_data = body.get("request_data", {})
    query_id = request_data.get("query_id", "")
    result = xql_queries.get_query_results(query_id)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, f"Query {query_id} not found"),
        )
    return result


@router.post("/xql/get_quota")
def get_quota(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Get XQL query quota information."""
    return xql_queries.get_quota()
