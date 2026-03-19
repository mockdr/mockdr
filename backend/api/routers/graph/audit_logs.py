"""Microsoft Graph Audit Logs endpoints (Sign-In Logs + Directory Audits)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api.graph_auth import require_graph_feature
from application.graph.audit_logs import queries as audit_log_queries

router = APIRouter(tags=["Graph Audit Logs"])


@router.get("/v1.0/auditLogs/signIns")
async def list_sign_in_logs(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    orderby: str = Query(None, alias="$orderby"),
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_graph_feature("auditLogs/signIns")),
) -> dict:
    """List sign-in logs with OData query parameters."""
    return audit_log_queries.list_sign_in_logs(
        filter_str=filter_str, top=top, skip=skip,
        orderby=orderby, select=select,
    )


@router.get("/v1.0/auditLogs/directoryAudits")
async def list_directory_audits(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    orderby: str = Query(None, alias="$orderby"),
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_graph_feature("auditLogs/directoryAudits")),
) -> dict:
    """List directory audit logs with OData query parameters."""
    return audit_log_queries.list_audit_logs(
        filter_str=filter_str, top=top, skip=skip,
        orderby=orderby, select=select,
    )
