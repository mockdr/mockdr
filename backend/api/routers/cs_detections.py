"""CrowdStrike Falcon Detection (Alert) API router.

Implements the alerts/queries, alerts/entities, and alerts update endpoints
matching the real CrowdStrike Falcon API path structure.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from api.cs_auth import require_cs_auth, require_cs_write
from application.cs_detections import commands as detection_commands
from application.cs_detections import queries as detection_queries
from utils.vendor_errors import build_vendor_error

router = APIRouter(tags=["CrowdStrike Detections"])


def _id_list(body: dict) -> list[str]:
    """Read the alert ids from a request body.

    An explicit ``null`` defeats a dict default, so ``composite_ids: null``
    produced None and iterating it raised TypeError out of the handler.
    """
    raw = body.get("composite_ids")
    if raw is None:
        raw = body.get("ids")
    return [str(i) for i in raw] if isinstance(raw, (list, tuple)) else []


@router.get("/alerts/queries/alerts/v2")
def query_detections(
    filter: str = Query(None),
    offset: int = Query(0),
    limit: int = Query(100, ge=1, le=1000),
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
    ids: list[str] = _id_list(body)
    return detection_queries.get_detection_entities(ids)


@router.patch("/alerts/entities/alerts/v3")
def update_detections(
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Update alert status, assignment, tags, or add a comment.

    CrowdStrike sends the changes as ``action_parameters`` — a list of
    ``{name, value}`` pairs — not as top-level fields. The flat shape this read
    is not what any real client sends, so a genuine request was accepted with
    a 200 and changed nothing.
    """
    ids: list[str] = _id_list(body)
    try:
        return detection_commands.update_detections(
            ids=ids,
            action_parameters=body.get("action_parameters"),
            status=body.get("status"),
            assigned_to_uuid=body.get("assigned_to_uuid"),
            comment=body.get("comment"),
        )
    except detection_commands.UnknownAlertActionError as exc:
        raise HTTPException(
            status_code=400,
            detail=build_vendor_error("crowdstrike", 400, str(exc)),
        ) from exc
