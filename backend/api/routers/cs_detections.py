"""CrowdStrike Falcon Detection (Alert) API router.

Implements the alerts/queries, alerts/entities, and alerts update endpoints
matching the real CrowdStrike Falcon API path structure.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Query

from api.cs_auth import require_cs_auth, require_cs_write
from application.cs_detections import commands as detection_commands
from application.cs_detections import queries as detection_queries

router = APIRouter(tags=["CrowdStrike Detections"])


@router.get("/alerts/queries/alerts/v2")
def query_detections(
    filter: str = Query(None),
    offset: int = Query(0),
    limit: int = Query(100, le=1000),
    sort: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return detection composite IDs matching an optional FQL filter."""
    return detection_queries.query_detection_ids(filter, offset, limit, sort)


@router.post("/alerts/entities/alerts/v2")
def get_detections(
    body: dict = Body(...),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return full detection entities for the given composite IDs."""
    ids: list[str] = body.get("composite_ids", body.get("ids", []))
    return detection_queries.get_detection_entities(ids)


@router.patch("/alerts/entities/alerts/v3")
def update_detections(
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Update detection status, assignment, or add a comment."""
    ids: list[str] = body.get("composite_ids", body.get("ids", []))
    return detection_commands.update_detections(
        ids=ids,
        status=body.get("status"),
        assigned_to_uuid=body.get("assigned_to_uuid"),
        comment=body.get("comment"),
    )
