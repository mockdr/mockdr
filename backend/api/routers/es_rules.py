"""Elastic Security Detection Engine Rules API router.

Implements Kibana Security Detection Engine rule management endpoints:
CRUD, find, bulk actions, tags, and prepackaged status.
"""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request

from api.es_auth import require_es_auth, require_es_write, require_kbn_xsrf
from application.es_rules import commands as rule_commands
from application.es_rules import queries as rule_queries
from domain.es_rule import EsRule
from repository.es_rule_repo import es_rule_repo
from utils.es_response import build_kbn_error_response, build_security_solution_error
from utils.kibana_validation import RulesQueryError, validate_rules_find_query

_RULE_TYPES = frozenset({
    "eql", "query", "saved_query", "threshold", "threat_match", "machine_learning",
    "new_terms", "esql",
})
_RULE_TYPE_LIST = (
    "'eql' | 'query' | 'saved_query' | 'threshold' | 'threat_match' | 'machine_learning' "
    "| 'new_terms' | 'esql'"
)

#: The fields rules/_find sorts by, in the order zod lists them (measured).
_SORTABLE = (
    "created_at", "createdAt", "enabled", "execution_summary.last_execution.date",
    "execution_summary.last_execution.metrics.execution_gap_duration_s",
    "execution_summary.last_execution.metrics.total_indexing_duration_ms",
    "execution_summary.last_execution.metrics.total_search_duration_ms",
    "execution_summary.last_execution.status", "name", "risk_score", "riskScore",
    "severity", "updated_at", "updatedAt",
)
_BULK_ACTIONS = ("delete", "disable", "enable", "export", "duplicate", "edit", "run")

router = APIRouter(tags=["Elastic Detection Rules"])


# ── CRUD ─────────────────────────────────────────────────────────────────────


@router.get("/api/detection_engine/rules")
def get_rule(
    id: str = Query(None),
    rule_id: str = Query(None),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Get a single detection rule by id or rule_id."""
    if not id and not rule_id:
        # Kibana's message here is a *list* (measured on 8.15).
        raise HTTPException(status_code=400, detail={
            "message": ['either "id" or "rule_id" must be set'], "status_code": 400,
        })
    result = rule_queries.get_rule(id) if id else rule_queries.get_rule_by_rule_id(rule_id)
    if result is None:
        which = f'id: "{id}"' if id else f'rule_id: "{rule_id}"'
        raise HTTPException(
            status_code=404,
            detail=build_security_solution_error(404, f"{which} not found"),
        )
    return result


@router.post("/api/detection_engine/rules", dependencies=[Depends(require_kbn_xsrf)])
def create_rule(
    body: dict = Body(...),
    caller: dict = Depends(require_es_write),
) -> dict:
    """Create a new detection rule.

    ``RuleCreateProps`` requires name, description, type, risk_score and
    severity, plus the type-specific query. Everything used to be optional and
    silently defaulted, so ``{"name": "x"}`` created a rule with an empty
    query that would match nothing — reported as a success.
    """
    # The type is a zod discriminator and is checked first; an unknown or
    # missing one is reported before any other field (measured on 8.15).
    if body.get("type") not in _RULE_TYPES:
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, "[request body]: type: Invalid discriminator value. Expected " + _RULE_TYPE_LIST,
        ))
    missing = [f for f in _REQUIRED_RULE_FIELDS if not body.get(f)]
    if missing:
        raise HTTPException(
            status_code=400,
            detail=build_security_solution_error(
                400, f"Invalid value \"undefined\" supplied to \"{missing[0]}\"",
            ),
        )
    if body.get("type") in ("query", "saved_query", "eql", "esql") and not body.get(
        "query",
    ):
        raise HTTPException(
            status_code=400,
            detail=build_security_solution_error(
                400, 'Invalid value "undefined" supplied to "query"',
            ),
        )
    if body.get("rule_id") and rule_queries.get_rule_by_rule_id(body["rule_id"]):
        raise HTTPException(
            status_code=409,
            detail=build_security_solution_error(
                409, f"rule_id: \"{body['rule_id']}\" already exists",
            ),
        )
    return rule_commands.create_rule(body, _caller(caller))


#: Fields RuleCreateProps declares as required.
_REQUIRED_RULE_FIELDS = ("name", "description", "type", "severity", "risk_score")


@router.put("/api/detection_engine/rules", dependencies=[Depends(require_kbn_xsrf)])
def update_rule(
    body: dict = Body(...),
    caller: dict = Depends(require_es_write),
) -> dict:
    """Replace an existing detection rule.

    Either identifier will do — a client that only ever saw the rule it
    created knows its ``rule_id`` and not the internal ``id``, and demanding
    the latter answered 400 for a perfectly formed request.
    """
    return rule_commands.update_rule(_addressed_rule(body), body, _caller(caller))


@router.patch("/api/detection_engine/rules", dependencies=[Depends(require_kbn_xsrf)])
def patch_rule(
    body: dict = Body(...),
    caller: dict = Depends(require_es_write),
) -> dict:
    """Update part of a detection rule.

    This is how a client toggles one member without sending the rule back
    whole. With no route at all, a client doing that got 404 and could only
    fall back to a PUT that silently reset everything it left out.
    """
    return rule_commands.patch_rule(_addressed_rule(body), body, _caller(caller))


def _caller(auth: dict) -> str:
    """Who is writing. The auth context spells the name `user`."""
    return str(auth.get("user") or "elastic")


def _addressed_rule(body: dict) -> EsRule:
    """Resolve the rule a write body addresses, by either identifier."""
    rule_id = body.get("id")
    public_id = body.get("rule_id")
    if not rule_id and not public_id:
        raise HTTPException(status_code=400, detail={
            "message": ['either "id" or "rule_id" must be set'], "status_code": 400,
        })
    rule = (
        es_rule_repo.get(str(rule_id)) if rule_id
        else es_rule_repo.get_by_rule_id(str(public_id))
    )
    if rule is None:
        which = f'id: "{rule_id}"' if rule_id else f'rule_id: "{public_id}"'
        raise HTTPException(
            status_code=404,
            detail=build_security_solution_error(404, f"{which} not found"),
        )
    return rule


@router.delete("/api/detection_engine/rules", dependencies=[Depends(require_kbn_xsrf)])
def delete_rule(
    id: str = Query(None),
    rule_id: str = Query(None),
    _: dict = Depends(require_es_write),
) -> dict:
    """Delete a detection rule by its internal ID."""
    # Return the rule before deleting.
    if not id and not rule_id:
        raise HTTPException(status_code=400, detail={
            "message": ['either "id" or "rule_id" must be set'], "status_code": 400,
        })
    # rule_id is the public identifier and what clients usually delete by;
    # taking only id answered 400 for a perfectly formed request.
    result = rule_queries.get_rule(id) if id else rule_queries.get_rule_by_rule_id(rule_id)
    if result is None:
        which = f'id: "{id}"' if id else f'rule_id: "{rule_id}"'
        raise HTTPException(
            status_code=404,
            detail=build_security_solution_error(404, f"{which} not found"),
        )
    rule_commands.delete_rule(str(result["id"]))
    return result


# ── Find ─────────────────────────────────────────────────────────────────────


_ALLOWED_SORT_FIELDS = {
    "created_at",
    "updated_at",
    "name",
    "enabled",
    "severity",
    "risk_score",
    "rule_id",
    "execution_summary.last_execution.date",
}


@router.get("/api/detection_engine/rules/_find")
def find_rules(
    request: Request,
    # Untyped on purpose: FastAPI's own 422 would pre-empt the zod wording
    # this endpoint answers with, which is what a client parses.
    page: str = Query("1"),
    per_page: str = Query("20"),
    sort_field: str = Query(None),
    sort_order: str = Query(None),
    filter: str = Query(None),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Find detection rules with optional filtering and pagination.

    This endpoint validates with zod, not the io-ts the Cases API uses, so it
    words everything differently — and it refuses a `sort_field` without a
    `sort_order` in an envelope of its own. Both used to come back 200: the
    first sorted the other way round without saying so.
    """
    try:
        validate_rules_find_query(request.query_params)
    except RulesQueryError as exc:
        if exc.sort_pair:
            raise HTTPException(status_code=400, detail={
                "message": [str(exc)], "status_code": 400,
            }) from exc
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, str(exc),
        )) from exc
    return rule_queries.find_rules(
        page=int(float(page)),
        per_page=int(float(per_page)),
        sort_field=sort_field,
        sort_order=sort_order or "asc",
        filter_str=filter,
    )


# ── Bulk Actions ─────────────────────────────────────────────────────────────


@router.post("/api/detection_engine/rules/_bulk_action", dependencies=[Depends(require_kbn_xsrf)])
def bulk_action(
    body: dict = Body(...),
    caller: dict = Depends(require_es_write),
) -> dict:
    """Perform a bulk action on detection rules.

    Supported actions: ``enable``, ``disable``, ``delete``, ``duplicate``,
    ``export``.
    """
    action = body.get("action")
    ids = body.get("ids")
    if action not in _BULK_ACTIONS or (isinstance(ids, list) and not ids):
        # zod tries every member of the action union and reports each
        # failure; Kibana shows the first five and counts the rest
        # (measured: "… and 11 more" for an unknown action with empty ids).
        issues: list[str] = []
        for candidate in _BULK_ACTIONS:
            if isinstance(ids, list) and not ids:
                issues.append("ids: Array must contain at least 1 element(s)")
            if action != candidate:
                issues.append(f'action: Invalid literal value, expected "{candidate}"')
        shown = issues[:5]
        rest = len(issues) - len(shown)
        text = "[request body]: " + ", ".join(shown) + (f", and {rest} more" if rest > 0 else "")
        raise HTTPException(status_code=400, detail=build_kbn_error_response(400, text))
    if not action:
        raise HTTPException(
            status_code=400,
            detail=build_security_solution_error(400, "action is required"),
        )
    rule_ids = body.get("ids")
    query = body.get("query")
    try:
        return rule_commands.bulk_action(action, rule_ids, query, _caller(caller))
    except rule_commands.UnknownBulkActionError as exc:
        # An unknown action used to be 200 {"success": false}, so a typo read
        # as a successful call.
        raise HTTPException(
            status_code=400,
            detail=build_security_solution_error(400, str(exc)),
        ) from exc


# Kibana 8.15 answers 404 for `/api/detection_engine/rules/tags` — measured.
# The route that exists is `/api/detection_engine/tags`, which this mount
# serves; keeping a second spelling that the product refuses meant a client
# could build against a path that is not there.


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
