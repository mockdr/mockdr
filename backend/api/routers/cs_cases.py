"""CrowdStrike Falcon Cases (Messaging Center) API router.

Implements case management endpoints used by XSOAR for creating,
querying, and tagging support/investigation cases.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Query

from api.cs_auth import require_cs_auth, require_cs_write
from application.cs_cases import commands as case_commands
from application.cs_cases import queries as case_queries

router = APIRouter(tags=["CrowdStrike Cases"])


@router.get("/alerts/queries/cases/v1")
def query_case_ids(
    filter: str = Query(None),
    offset: int = Query(0),
    limit: int = Query(100, le=500),
    sort: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Query case IDs with optional FQL filter."""
    return case_queries.query_case_ids(filter, offset, limit, sort)


@router.post("/alerts/entities/cases/GET/v1")
def get_case_entities(
    body: dict = Body(...),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return full case entities by ID list (POST body)."""
    ids = body.get("ids", [])
    return case_queries.get_case_entities(ids)


@router.post("/alerts/entities/cases/v1")
def create_case(
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Create a new case."""
    return case_commands.create_case(body)


@router.patch("/alerts/entities/cases/v1")
def update_case(
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Update an existing case."""
    case_id = body.get("id", "")
    return case_commands.update_case(case_id, body)


@router.post("/alerts/entities/cases/tags/v1")
def add_case_tags(
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Add tags to a case.

    Body: ``{"id": "...", "tags": [...]}``.
    """
    case_id = body.get("id", "")
    tags = body.get("tags", [])
    return case_commands.add_case_tags(case_id, tags)


@router.delete("/alerts/entities/cases/tags/v1")
def delete_case_tags(
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Remove tags from a case.

    Body: ``{"id": "...", "tags": [...]}``.
    """
    case_id = body.get("id", "")
    tags = body.get("tags", [])
    return case_commands.delete_case_tags(case_id, tags)
