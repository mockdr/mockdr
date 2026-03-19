"""Microsoft Graph Service Principals endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api.graph_auth import require_graph_auth
from application.graph.service_principals import queries as sp_queries

router = APIRouter(tags=["Graph Service Principals"])


@router.get("/v1.0/servicePrincipals")
async def list_service_principals(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    orderby: str = Query(None, alias="$orderby"),
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List service principals with OData query parameters."""
    return sp_queries.list_service_principals(
        filter_str, top, skip, orderby, select,
    )
