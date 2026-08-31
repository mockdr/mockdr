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
            "assignees": {"add": ["user1"], "remove": ["user2"]}
        }

    Both member names are the product's: mockdr read `assignees_to_add` and
    `assignees_to_remove`, so an assignment written the way 8.15 takes it was
    read as no assignment at all and answered success.
    """
    _refuse_bad_assignees(body)
    assignees = body.get("assignees") or {}
    if not isinstance(assignees, dict):
        # The guard above only judges a dict, so a list or a string reached
        # `assignees.get("add")` and answered 500 where Kibana says
        # `assignees: Expected object, received array`.
        raise HTTPException(
            status_code=400,
            detail=build_kbn_error_response(
                400,
                f"assignees: Expected object, received "
                f"{'array' if isinstance(assignees, list) else type(assignees).__name__}",
            ),
        )
    # Stored as `{"uid": …}`, which is the shape an alert carries; the wire
    # names them as plain strings.
    return alert_commands.update_alert_assignees(
        body.get("ids") or [],
        assignees_to_add=[{"uid": uid} for uid in assignees.get("add") or []],
        assignees_to_remove=[{"uid": uid} for uid in assignees.get("remove") or []],
    )


#: What zod calls each JSON type in `Expected x, received y`.
_ZOD_TYPES = {
    dict: "object", list: "array", str: "string", bool: "boolean",
    int: "number", float: "number", type(None): "null",
}


def _assignee_list_issues(member: str, value: object) -> list[str]:
    """What zod says about one side of the assignment.

    Each is an array of user ids as *strings*. mockdr read them as objects
    carrying a `uid`, which is the shape it stores — so an assignment
    written the way 8.15 takes it raised out of the handler.
    """
    if not isinstance(value, list):
        kind = _ZOD_TYPES.get(type(value), "string")
        return [f"assignees.{member}: Expected array, received {kind}"]
    return [
        f"assignees.{member}.{i}: Expected string, received "
        f"{_ZOD_TYPES.get(type(entry), 'string')}"
        for i, entry in enumerate(value) if not isinstance(entry, str)
    ]


#: What this route declares, in the order zod reports it: the block first,
#: its two members inside it, then the ids. mockdr answered one hand-written
#: `ids is required` for every one of them.
def _refuse_bad_assignees(body: dict) -> None:
    """Refuse an assignment body the way 8.15's schema refuses it.

    Raises:
        HTTPException: 400, in Kibana's own wording.
    """
    issues: list[str] = []
    if "assignees" not in body:
        issues.append("assignees: Required")
    elif isinstance(body["assignees"], dict):
        for member in ("add", "remove"):
            if member not in body["assignees"]:
                issues.append(f"assignees.{member}: Required")
                continue
            issues += _assignee_list_issues(member, body["assignees"][member])
    if "ids" not in body:
        issues.append("ids: Required")
    if issues:
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, "[request body]: " + ", ".join(issues),
        ))
