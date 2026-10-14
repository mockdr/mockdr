"""Microsoft Graph Service Principals endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api.graph_auth import require_graph_auth
from application.graph.service_principals import queries as sp_queries
from utils.odata_paging import directory_page_offset

router = APIRouter(tags=["Graph Service Principals"])


@router.get("/v1.0/servicePrincipals")
async def list_service_principals(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", ge=1, le=999),
    skip: int = Depends(directory_page_offset),
    orderby: str = Query(None, alias="$orderby"),
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List service principals with OData query parameters."""
    return sp_queries.list_service_principals(
        filter_str, top, skip, orderby, select,
    )
