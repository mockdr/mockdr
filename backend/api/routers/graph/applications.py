"""Microsoft Graph Applications (App Registrations) endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api.graph_auth import require_graph_auth
from application.graph.applications import queries as app_queries

router = APIRouter(tags=["Graph Applications"])


@router.get("/v1.0/applications")
async def list_applications(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List application registrations with OData query parameters."""
    return app_queries.list_applications(
        filter_str=filter_str,
        top=top,
        skip=skip,
        select=select,
    )
