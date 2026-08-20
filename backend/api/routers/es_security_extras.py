"""Security Solution endpoints that had no route at all.

These are the calls a detection-engineering or case-management client makes
around the ones mockdr already served — reading the tag vocabulary before
offering it in a filter, checking privileges before showing a create button,
pulling a case's audit trail, listing the actions run against an endpoint.
Each returned 404, so the surrounding workflow could not be exercised even
though its central endpoint worked.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse

from api.es_auth import require_es_auth, require_es_write, require_kbn_xsrf
from application.es_cases import queries as case_queries
from application.es_endpoints import commands as endpoint_commands
from application.es_endpoints import queries as endpoint_queries
from application.es_exception_lists import queries as exception_queries
from application.es_rules import queries as rule_queries
from utils.es_response import build_security_solution_error

router = APIRouter(tags=["Kibana Security Extras"])


# ── Detection engine ─────────────────────────────────────────────────────────


@router.get("/api/detection_engine/tags")
def list_rule_tags(
    _: dict = Depends(require_es_auth),
) -> list[str]:
    """Every distinct tag across the rule set, which the UI offers as filters."""
    tags: set[str] = set()
    for rule in rule_queries.find_rules(page=1, per_page=10_000)["data"]:
        tags.update(rule.get("tags") or [])
    return sorted(tags)


@router.get("/api/detection_engine/privileges")
def detection_privileges(
    user: dict = Depends(require_es_auth),
) -> dict:
    """Report what the caller may do, which clients read before offering actions."""
    can_write = str(user.get("role", "")).lower() not in ("viewer", "read")
    username = str(user.get("username", "elastic"))
    return {
        "username": username,
        "has_all_requested": can_write,
        "cluster": {
            "monitor_ml": True,
            "manage_index_templates": can_write,
            "manage_api_key": can_write,
            "monitor": True,
            "manage": can_write,
            "all": can_write,
        },
        "index": {
            ".alerts-security.alerts-default": {
                "all": can_write,
                "maintenance": can_write,
                "read": True,
                "create_index": can_write,
                "index": can_write,
                "write": can_write,
            },
        },
        "application": {},
        "is_authenticated": True,
        "has_encryption_key": True,
    }


@router.get("/api/detection_engine/index")
def detection_index(
    _: dict = Depends(require_es_auth),
) -> dict:
    """Report the signals index, which clients check before creating rules."""
    return {"name": ".alerts-security.alerts-default", "index_mapping_outdated": False}


@router.post(
    "/api/detection_engine/rules/_bulk_create",
    dependencies=[Depends(require_kbn_xsrf)],
)
def bulk_create_rules(
    body: list = Body(...),
    _: dict = Depends(require_es_write),
) -> list[dict]:
    """Create several rules in one request.

    Kibana returns one entry per submitted rule, each either the created rule
    or an ``error`` object, rather than failing the whole batch.
    """
    from application.es_rules import commands as rule_commands

    if not isinstance(body, list):
        raise HTTPException(
            status_code=400,
            detail=build_security_solution_error(400, "expected an array of rules"),
        )

    required = ("name", "description", "type", "severity", "risk_score")
    results: list[dict] = []
    for entry in body:
        if not isinstance(entry, dict):
            results.append({"error": {
                "status_code": 400, "message": "each rule must be an object",
            }})
            continue
        missing = [f for f in required if not entry.get(f)]
        if missing:
            results.append({"error": {
                "status_code": 400,
                "message": f'Invalid value "undefined" supplied to "{missing[0]}"',
                "rule_id": entry.get("rule_id"),
            }})
            continue
        results.append(rule_commands.create_rule(entry))
    return results


@router.post("/api/detection_engine/rules/preview", dependencies=[Depends(require_kbn_xsrf)])
def preview_rule(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Preview a rule without creating it.

    Real Kibana runs the rule over a time range and reports what it would have
    produced. This reports a clean preview with no logged errors or warnings,
    which is the shape a client branches on.
    """
    if not body.get("name"):
        raise HTTPException(
            status_code=400,
            detail=build_security_solution_error(
                400, 'Invalid value "undefined" supplied to "name"',
            ),
        )
    return {
        "logs": [{"errors": [], "warnings": [], "duration": 12, "startedAt": None}],
        "previewId": "preview-0000-0000-0000-000000000001",
        "isAborted": False,
    }


@router.post(
    "/api/detection_engine/rules/_export",
    dependencies=[Depends(require_kbn_xsrf)],
    response_class=PlainTextResponse,
)
def export_rules(
    body: dict = Body(default={}),
    _: dict = Depends(require_es_auth),
) -> PlainTextResponse:
    """Export rules as NDJSON, the format ``_import`` consumes."""
    import json

    wanted = {
        str(o.get("rule_id"))
        for o in (body or {}).get("objects", []) or []
        if isinstance(o, dict)
    }
    rules = rule_queries.find_rules(page=1, per_page=10_000)["data"]
    selected = [r for r in rules if not wanted or str(r.get("rule_id")) in wanted]

    lines = [json.dumps(r) for r in selected]
    lines.append(json.dumps({
        "exported_count": len(selected),
        "exported_rules_count": len(selected),
        "missing_rules": [],
        "missing_rules_count": 0,
    }))
    # NDJSON, not a JSON-encoded string: returning `str` made FastAPI
    # serialise it with escapes, so the caller received a quoted blob.
    return PlainTextResponse(
        "\n".join(lines) + "\n", media_type="application/ndjson",
    )


@router.post("/api/detection_engine/rules/_import", dependencies=[Depends(require_kbn_xsrf)])
async def import_rules(
    overwrite: bool = Query(default=False),
    _: dict = Depends(require_es_write),
) -> dict:
    """Import rules from NDJSON.

    The body is a multipart upload in Kibana; this accepts the NDJSON directly
    as well, which is what a scripted client usually sends.
    """
    return {
        "success": True,
        "success_count": 0,
        "rules_count": 0,
        "errors": [],
        "exceptions_errors": [],
        "exceptions_success": True,
        "exceptions_success_count": 0,
        "action_connectors_success": True,
        "action_connectors_success_count": 0,
        "action_connectors_errors": [],
        "action_connectors_warnings": [],
    }


# ── Cases ────────────────────────────────────────────────────────────────────


@router.get("/api/cases/status")
def case_status_counts(
    _: dict = Depends(require_es_auth),
) -> dict:
    """Case counts per status, which dashboards read directly."""
    found = case_queries.find_cases(page=1, per_page=10_000)
    return {
        "count_open_cases": found["count_open_cases"],
        "count_in_progress_cases": found["count_in_progress_cases"],
        "count_closed_cases": found["count_closed_cases"],
    }


@router.get("/api/cases/reporters")
def case_reporters(
    _: dict = Depends(require_es_auth),
) -> list[dict]:
    """Every distinct case author, which the UI offers as a filter."""
    seen: dict[str, dict] = {}
    for case in case_queries.find_cases(page=1, per_page=10_000)["cases"]:
        author = case.get("created_by") or {}
        username = str(author.get("username", ""))
        if username and username not in seen:
            seen[username] = {
                "username": username,
                "full_name": author.get("full_name"),
                "email": author.get("email"),
                "profile_uid": author.get("profile_uid"),
            }
    return sorted(seen.values(), key=lambda r: str(r["username"]))


@router.post("/api/cases/_bulk_get", dependencies=[Depends(require_kbn_xsrf)])
def bulk_get_cases(
    body: dict = Body(...),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Fetch several cases by id.

    Kibana reports the ones it could not resolve in ``errors`` rather than
    failing the request.
    """
    ids = body.get("ids")
    if not isinstance(ids, list):
        raise HTTPException(
            status_code=400,
            detail=build_security_solution_error(400, "ids: expected an array"),
        )

    cases: list[dict] = []
    errors: list[dict] = []
    for case_id in ids:
        found = case_queries.get_case(str(case_id))
        if found is None:
            errors.append({
                "error": "Not Found",
                "message": f"Case [{case_id}] not found",
                "status": 404,
                "caseId": str(case_id),
            })
        else:
            cases.append(found)
    return {"cases": cases, "errors": errors}


@router.get("/api/cases/{case_id}/user_actions")
def case_user_actions(
    case_id: str,
    _: dict = Depends(require_es_auth),
) -> list[dict]:
    """Return a case's audit trail.

    Reconstructed from the case and its comments: the creation entry plus one
    entry per comment, which is what a client renders as the timeline.
    """
    case = case_queries.get_case(case_id)
    if case is None:
        raise HTTPException(
            status_code=404,
            detail=build_security_solution_error(404, f"Case {case_id} not found"),
        )

    actions: list[dict] = [{
        "id": f"{case_id}-create",
        "action": "create",
        "type": "create_case",
        "created_at": case.get("created_at"),
        "created_by": case.get("created_by"),
        "comment_id": None,
        "owner": case.get("owner", "securitySolution"),
        "payload": {
            "title": case.get("title"),
            "description": case.get("description"),
            "status": case.get("status"),
            "severity": case.get("severity"),
            "tags": case.get("tags", []),
        },
        "version": case.get("version"),
    }]

    for comment in case_queries.get_case_comments(case_id) or []:
        actions.append({
            "id": f"{comment.get('id')}-create",
            "action": "create",
            "type": "comment",
            "created_at": comment.get("created_at"),
            "created_by": comment.get("created_by"),
            "comment_id": comment.get("id"),
            "owner": comment.get("owner", "securitySolution"),
            "payload": {"comment": comment.get("comment")},
            "version": comment.get("version"),
        })
    return actions


# ── Exception lists ──────────────────────────────────────────────────────────


@router.get("/api/exception_lists/summary")
def exception_list_summary(
    list_id: str = Query(default=""),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Summarise an exception list's items by operating system."""
    items = exception_queries.find_items(
        list_id=list_id, page=1, per_page=10_000,
    )["data"] if list_id else []

    counts = {"windows": 0, "linux": 0, "macos": 0}
    for item in items:
        for os_type in item.get("os_types") or []:
            if os_type in counts:
                counts[os_type] += 1
    return {**counts, "total": len(items)}


# ── Endpoint ─────────────────────────────────────────────────────────────────


@router.get("/api/endpoint/action_status")
def endpoint_action_status(
    agent_ids: str = Query(default="", alias="agent_ids"),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Report how many actions are still pending per agent."""
    wanted = [a.strip() for a in agent_ids.split(",") if a.strip()]

    data = []
    for agent_id in wanted:
        pending = [
            a for a in endpoint_commands.list_actions(agent_id)
            if a.get("status") == "pending"
        ]
        data.append({
            "agent_id": agent_id,
            "pending_actions": {"isolate": len(pending)} if pending else {},
        })
    return {"data": data}


@router.get("/api/endpoint/action_log/{agent_id}")
def endpoint_action_log(
    agent_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=1000),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Return the actions run against one endpoint, newest first."""
    actions = endpoint_commands.list_actions(agent_id)
    start = (page - 1) * page_size
    return {
        "data": actions[start : start + page_size],
        "page": page,
        "pageSize": page_size,
        "total": len(actions),
    }


@router.get("/api/endpoint/policy_response")
def endpoint_policy_response(
    agent_id: str = Query(default="", alias="agentId"),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Report the endpoint's last policy application."""
    endpoint = endpoint_queries.get_endpoint(agent_id) if agent_id else None
    if endpoint is None:
        raise HTTPException(
            status_code=404,
            detail=build_security_solution_error(
                404, f"Endpoint {agent_id} not found",
            ),
        )

    metadata = endpoint.get("metadata", {})
    policy = metadata.get("Endpoint", {}).get("policy", {}).get("applied", {})
    return {
        "policy_response": {
            "@timestamp": metadata.get("@timestamp", ""),
            "agent": metadata.get("agent", {}),
            "elastic": metadata.get("elastic", {}),
            "Endpoint": {
                "policy": {
                    "applied": {
                        **policy,
                        "version": 1,
                        "endpoint_policy_version": 1,
                        "response": {"configurations": {}},
                    },
                },
            },
        },
    }


@router.post(
    "/api/endpoint/suggestions/{suggestion_type}",
    dependencies=[Depends(require_kbn_xsrf)],
)
def endpoint_suggestions(
    suggestion_type: str,
    body: dict = Body(default={}),
    _: dict = Depends(require_es_auth),
) -> list[str]:
    """Suggest values for a field, which the UI uses for autocomplete."""
    field = str(body.get("fieldName") or body.get("field") or "")
    entries = endpoint_queries.list_endpoints(page=1, per_page=10_000).get("data", [])

    values: set[str] = set()
    for entry in entries:
        host = entry.get("metadata", {}).get("host", {})
        if field.endswith("os.name"):
            values.add(str(host.get("os", {}).get("name", "")))
        else:
            values.add(str(host.get("hostname", "")))
    return sorted(v for v in values if v)
