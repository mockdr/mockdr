"""CrowdStrike Falcon User Management API router.

Implements the ``/user-management/`` endpoints used by XSOAR for
querying and retrieving Falcon console user accounts.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Query

from api.cs_auth import require_cs_auth
from application.cs_users import queries as user_queries

router = APIRouter(tags=["CrowdStrike Users"])


@router.get("/user-management/queries/users/v1")
def query_user_ids(
    filter: str = Query(None),
    offset: int = Query(0),
    limit: int = Query(100, le=500),
    sort: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Query user UUIDs with optional FQL filter."""
    return user_queries.query_user_ids(filter, offset, limit, sort)


@router.post("/user-management/entities/users/GET/v1")
def get_user_entities(
    body: dict = Body(...),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return full user entities by UUID list (POST body)."""
    ids = body.get("ids", [])
    return user_queries.get_user_entities(ids)


@router.get("/user-management/entities/users/v1")
def get_user_entities_get(
    ids: str = Query(...),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return full user entities by comma-separated UUIDs (GET)."""
    id_list = [i.strip() for i in ids.split(",") if i.strip()]
    return user_queries.get_user_entities(id_list)
