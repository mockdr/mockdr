"""Elastic Security Detection Engine Signals (Alerts) API router.

Implements Kibana Security signal management endpoints: search, status
update, tag management, and assignee management.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException

from api.es_auth import require_es_auth, require_es_write, require_kbn_xsrf
from application.es_alerts import commands as alert_commands
from application.es_alerts import queries as alert_queries
from utils.es_response import build_es_error_response

router = APIRouter(tags=["Elastic Alerts"])


# ── Search ───────────────────────────────────────────────────────────────────


@router.post("/api/detection_engine/signals/search")
def search_alerts(
    body: dict = Body(...),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Search alerts using Elasticsearch query DSL."""
    return alert_queries.search_alerts(body)


# ── Status ───────────────────────────────────────────────────────────────────


@router.post("/api/detection_engine/signals/status", dependencies=[Depends(require_kbn_xsrf)])
def update_alert_status(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Update the workflow status of one or more alerts.

    Body format::

        {
            "signal_ids": ["id1", "id2"],
            "status": "closed"
        }
    """
    signal_ids = body.get("signal_ids", [])
    status = body.get("status")
    if not signal_ids or not status:
        raise HTTPException(
            status_code=400,
            detail=build_es_error_response(
                400, "bad_request", "signal_ids and status are required",
            ),
        )
    return alert_commands.update_alert_status(signal_ids, status)


# ── Tags ─────────────────────────────────────────────────────────────────────


@router.post("/api/detection_engine/signals/tags", dependencies=[Depends(require_kbn_xsrf)])
def update_alert_tags(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Add or remove tags on one or more alerts.

    Body format::

        {
            "ids": ["id1", "id2"],
            "tags": {"tags_to_add": ["tag1"], "tags_to_remove": ["tag2"]}
        }
    """
    alert_ids = body.get("ids", [])
    tags = body.get("tags", {})
    if not alert_ids:
        raise HTTPException(
            status_code=400,
            detail=build_es_error_response(400, "bad_request", "ids is required"),
        )
    return alert_commands.update_alert_tags(
        alert_ids,
        tags_to_add=tags.get("tags_to_add", []),
        tags_to_remove=tags.get("tags_to_remove", []),
    )


# ── Assignees ────────────────────────────────────────────────────────────────


@router.post("/api/detection_engine/signals/assignees", dependencies=[Depends(require_kbn_xsrf)])
def update_alert_assignees(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Add or remove assignees on one or more alerts.

    Body format::

        {
            "ids": ["id1", "id2"],
            "assignees": {
                "assignees_to_add": [{"uid": "user1"}],
                "assignees_to_remove": [{"uid": "user2"}]
            }
        }
    """
    alert_ids = body.get("ids", [])
    assignees = body.get("assignees", {})
    if not alert_ids:
        raise HTTPException(
            status_code=400,
            detail=build_es_error_response(400, "bad_request", "ids is required"),
        )
    return alert_commands.update_alert_assignees(
        alert_ids,
        assignees_to_add=assignees.get("assignees_to_add", []),
        assignees_to_remove=assignees.get("assignees_to_remove", []),
    )
