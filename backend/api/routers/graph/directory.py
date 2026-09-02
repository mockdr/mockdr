"""Microsoft Graph Directory Roles endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api.graph_auth import require_graph_auth
from application.graph.directory import queries as directory_queries

router = APIRouter(tags=["Graph Directory"])


@router.get("/v1.0/directoryRoles")
async def list_directory_roles(
    top: int = Query(100, alias="$top", ge=1, le=999),
    skip: int = Query(0, alias="$skip", ge=0),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List activated directory roles."""
    return directory_queries.list_directory_roles(top, skip)


@router.get("/v1.0/directoryRoles/{role_id}/members")
async def list_directory_role_members(
    role_id: str,
    top: int = Query(100, alias="$top", ge=1, le=999),
    skip: int = Query(0, alias="$skip", ge=0),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List members of a directory role."""
    return directory_queries.get_role_members(role_id, top, skip)
