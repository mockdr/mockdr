"""Elastic Security Detection Engine Rules API router.

Implements Kibana Security Detection Engine rule management endpoints:
CRUD, find, bulk actions, tags, and prepackaged status.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from api.es_auth import require_es_auth, require_es_write, require_kbn_xsrf
from application.es_rules import commands as rule_commands
from application.es_rules import queries as rule_queries
from utils.es_response import build_es_error_response

router = APIRouter(tags=["Elastic Detection Rules"])


# ── CRUD ─────────────────────────────────────────────────────────────────────


@router.get("/api/detection_engine/rules")
def get_rule(
    id: str = Query(None),
    rule_id: str = Query(None),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Get a single detection rule by id or rule_id."""
    result = None
    if id:
        result = rule_queries.get_rule(id)
    elif rule_id:
        result = rule_queries.get_rule_by_rule_id(rule_id)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_es_error_response(404, "not_found", "rule not found"),
        )
    return result


@router.post("/api/detection_engine/rules", dependencies=[Depends(require_kbn_xsrf)])
def create_rule(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Create a new detection rule."""
    return rule_commands.create_rule(body)


@router.put("/api/detection_engine/rules", dependencies=[Depends(require_kbn_xsrf)])
def update_rule(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Update an existing detection rule."""
    rule_id = body.get("id")
    if not rule_id:
        raise HTTPException(
            status_code=400,
            detail=build_es_error_response(
                400, "bad_request", "id is required in the request body",
            ),
        )
    result = rule_commands.update_rule(rule_id, body)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_es_error_response(404, "not_found", f"rule {rule_id} not found"),
        )
    return result


@router.delete("/api/detection_engine/rules", dependencies=[Depends(require_kbn_xsrf)])
def delete_rule(
    id: str = Query(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Delete a detection rule by its internal ID."""
    # Return the rule before deleting.
    result = rule_queries.get_rule(id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_es_error_response(404, "not_found", f"rule {id} not found"),
        )
    rule_commands.delete_rule(id)
    return result


# ── Find ─────────────────────────────────────────────────────────────────────


_ALLOWED_SORT_FIELDS = {
    "created_at", "updated_at", "name", "enabled", "severity",
    "risk_score", "rule_id", "execution_summary.last_execution.date",
}


@router.get("/api/detection_engine/rules/_find")
def find_rules(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=1000),
    sort_field: str = Query(None),
    sort_order: str = Query("asc"),
    filter: str = Query(None),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Find detection rules with optional filtering and pagination."""
    if sort_field and sort_field not in _ALLOWED_SORT_FIELDS:
        raise HTTPException(
            status_code=400,
            detail=build_es_error_response(
                400, "bad_request",
                f"Invalid sort_field '{sort_field}'. "
                f"Allowed: {', '.join(sorted(_ALLOWED_SORT_FIELDS))}",
            ),
        )
    return rule_queries.find_rules(
        page=page,
        per_page=per_page,
        sort_field=sort_field,
        sort_order=sort_order,
        filter_str=filter,
    )


# ── Bulk Actions ─────────────────────────────────────────────────────────────


@router.post("/api/detection_engine/rules/_bulk_action", dependencies=[Depends(require_kbn_xsrf)])
def bulk_action(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Perform a bulk action on detection rules.

    Supported actions: ``enable``, ``disable``, ``delete``, ``export``.
    """
    action = body.get("action")
    if not action:
        raise HTTPException(
            status_code=400,
            detail=build_es_error_response(400, "bad_request", "action is required"),
        )
    rule_ids = body.get("ids")
    query = body.get("query")
    return rule_commands.bulk_action(action, rule_ids, query)


# ── Tags ─────────────────────────────────────────────────────────────────────


@router.get("/api/detection_engine/rules/tags")
def get_tags(
    _: dict = Depends(require_es_auth),
) -> list[str]:
    """Return all unique tags across all detection rules."""
    return rule_queries.get_tags()


# ── Prepackaged Status ───────────────────────────────────────────────────────


@router.get("/api/detection_engine/rules/prepackaged/_status")
def prepackaged_status(
    _: dict = Depends(require_es_auth),
) -> dict:
    """Return the status of prepackaged (Elastic) rules.

    Returns static counts matching the real Elastic API format.
    """
    return {
        "rules_custom_installed": rule_queries.find_rules(per_page=1).get("total", 0),
        "rules_installed": 0,
        "rules_not_installed": 0,
        "rules_not_updated": 0,
        "timelines_installed": 0,
        "timelines_not_installed": 0,
        "timelines_not_updated": 0,
    }
