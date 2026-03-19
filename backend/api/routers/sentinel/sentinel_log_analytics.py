"""Sentinel Log Analytics KQL query router."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from api.sentinel_auth import require_sentinel_auth
from application.sentinel.queries.log_analytics import query_logs

router = APIRouter(tags=["Sentinel Log Analytics"])


@router.post("/v1/workspaces/{workspace_id}/query")
async def run_query(
    workspace_id: str,
    request: Request,
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Execute a KQL query against the workspace."""
    body = await request.json()
    kql = body.get("query", "")
    return query_logs(kql)
