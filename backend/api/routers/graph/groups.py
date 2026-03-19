"""Microsoft Graph Groups endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from api.graph_auth import require_graph_auth
from application.graph.groups import queries as group_queries
from utils.graph_response import build_graph_error_response

router = APIRouter(tags=["Graph Groups"])


@router.get("/v1.0/groups")
async def list_groups(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    orderby: str = Query(None, alias="$orderby"),
    select: str = Query(None, alias="$select"),
    search: str = Query(None, alias="$search"),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List groups with OData query parameters."""
    return group_queries.list_groups(
        filter_str=filter_str, top=top, skip=skip,
        orderby=orderby, select=select, search=search,
    )


@router.get("/v1.0/groups/{group_id}")
async def get_group(
    group_id: str,
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """Get a single group by ID."""
    result = group_queries.get_group(group_id)
    if result is None:
        raise HTTPException(
            404,
            detail=build_graph_error_response("NotFound", f"Group '{group_id}' not found"),
        )
    return result


@router.get("/v1.0/groups/{group_id}/members")
async def list_group_members(
    group_id: str,
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List members of a group."""
    return group_queries.get_group_members(group_id)
