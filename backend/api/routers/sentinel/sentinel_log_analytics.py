"""Sentinel Log Analytics KQL query router."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from api.sentinel_auth import require_sentinel_auth
from application.sentinel.queries.log_analytics import UnknownTableError, query_logs
from utils.sentinel.kql_parser import UnsupportedKqlError
from utils.vendor_errors import build_vendor_error

router = APIRouter(tags=["Sentinel Log Analytics"])


@router.post("/v1/workspaces/{workspace_id}/query")
async def run_query(
    workspace_id: str,
    request: Request,
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Execute a KQL query against the workspace."""
    body = await request.json()
    if not isinstance(body, dict):
        # A JSON null or array reached `.get` on the wrong type and 500ed.
        raise HTTPException(
            status_code=400,
            detail=build_vendor_error("sentinel", 400, "Request body must be a JSON object"),
        )
    kql = body.get("query") or ""
    if not isinstance(kql, str) or not kql.strip():
        # Log Analytics refuses a missing or empty query as a bad argument.
        raise HTTPException(
            status_code=400,
            detail=build_vendor_error(
                "sentinel", 400, "The request had some invalid properties: query is required",
            ),
        )
    try:
        return query_logs(kql)
    except UnsupportedKqlError as exc:
        # A clause this parser cannot evaluate.  Dropping it answered 200
        # with rows that do not match what was asked — `contains 'zzzzz'`
        # returned the whole table.  Log Analytics answers a query it cannot
        # compile with 400, and so does this.
        raise HTTPException(
            status_code=400,
            detail=build_vendor_error(
                "sentinel", 400,
                f"The request had some invalid properties: {exc}"),
        ) from exc
    except UnknownTableError as exc:
        # Log Analytics answers a query naming no table it has with a bad
        # argument, not with an empty result set.
        raise HTTPException(
            status_code=400,
            detail=build_vendor_error(
                "sentinel", 400, f"The request had some invalid properties: {exc}"),
        ) from exc
