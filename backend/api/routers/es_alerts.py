"""Elastic Security Detection Engine Signals (Alerts) API router.

Implements Kibana Security signal management endpoints: search, status
update, tag management, and assignee management.
"""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException

from api.es_auth import require_es_auth, require_es_write, require_kbn_xsrf
from application.es_alerts import commands as alert_commands
from application.es_alerts import queries as alert_queries
from utils.es_response import build_kbn_error_response

router = APIRouter(tags=["Elastic Alerts"])


# ── Search ───────────────────────────────────────────────────────────────────


@router.post("/api/detection_engine/signals/search")
def search_alerts(
    body: dict = Body(...),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Search alerts using Elasticsearch query DSL."""
    if not body:
        # Joi's wording, verbatim (measured on 8.15).
        raise HTTPException(status_code=400, detail={
            "message": '"value" must have at least 1 children', "status_code": 400,
        })
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
    _refuse_bad_status_body(body)
    return alert_commands.update_alert_status(
        body.get("signal_ids") or [], str(body.get("status") or ""),
    )


#: The workflow states 8.15 takes here, in the order its message lists them.
_ALERT_STATUSES = ("open", "closed", "acknowledged", "in-progress")

#: The two shapes this route accepts: alerts named by id, or alerts matched
#: by a query. zod tries both and reports what each arm complained about, one
#: after the other — which is why a body with nothing in it reads as four
#: failures rather than two.
_STATUS_ARMS: tuple[tuple[str, ...], ...] = (("signal_ids", "status"), ("query", "status"))


def _status_issue(body: dict, field: str) -> str | None:
    """What zod says about one member of one arm, or nothing if it is fine."""
    if field not in body:
        return f"{field}: Required"
    value = body[field]
    if field == "signal_ids" and not isinstance(value, list):
        kind = {str: "string", int: "number", dict: "object", bool: "boolean"}
        return f"signal_ids: Expected array, received {kind.get(type(value), 'string')}"
    if field == "status" and value not in _ALERT_STATUSES:
        allowed = " | ".join(f"'{s}'" for s in _ALERT_STATUSES)
        return (
            f"status: Invalid enum value. Expected {allowed}, received '{value}'"
        )
    return None


def _refuse_bad_status_body(body: dict) -> None:
    """Refuse a status update the way 8.15's schema refuses it.

    mockdr answered one hand-written line — `signal_ids and status are
    required` — for every one of these, where the product names each member
    of each arm. An empty `signal_ids` is the one case that reports the first
    arm alone; measured rather than derived, because the rule the others
    follow would have named the second arm too.

    Raises:
        HTTPException: 400, in Kibana's own wording.
    """
    if isinstance(body.get("signal_ids"), list) and not body["signal_ids"]:
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, "[request body]: signal_ids: Array must contain at least 1 element(s)",
        ))
    per_arm = [
        [issue for field in arm if (issue := _status_issue(body, field)) is not None]
        for arm in _STATUS_ARMS
    ]
    # One arm satisfied is enough; only when both fail does the message list
    # what each of them wanted.
    if any(not arm for arm in per_arm):
        return
    issues = [issue for arm in per_arm for issue in arm]
    if issues:
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, "[request body]: " + ", ".join(issues),
        ))


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
            detail=build_kbn_error_response(400, "ids is required"),
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
            detail=build_kbn_error_response(400, "ids is required"),
        )
    return alert_commands.update_alert_assignees(
        alert_ids,
        assignees_to_add=assignees.get("assignees_to_add", []),
        assignees_to_remove=assignees.get("assignees_to_remove", []),
    )
