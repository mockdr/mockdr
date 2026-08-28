"""Security Solution endpoints that had no route at all.

These are the calls a detection-engineering or case-management client makes
around the ones mockdr already served — reading the tag vocabulary before
offering it in a filter, checking privileges before showing a create button,
pulling a case's audit trail, listing the actions run against an endpoint.
Each returned 404, so the surrounding workflow could not be exercised even
though its central endpoint worked.
"""
from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from api.es_auth import require_es_auth, require_es_write, require_kbn_xsrf
from application.es_cases import queries as case_queries
from application.es_endpoints import commands as endpoint_commands
from application.es_endpoints import queries as endpoint_queries
from application.es_exception_lists import queries as exception_queries
from application.es_rules import queries as rule_queries
from repository.es_rule_repo import es_rule_repo
from utils.es_response import build_kbn_error_response, build_security_solution_error
from utils.kibana_query import INVALID_KEYS, refuses_unknown
from utils.kibana_validation import (
    ENDPOINT_ACTION_STATUS_QUERY,
    ConfigSchemaError,
    validate_config_schema,
)

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
    # require_es_auth returns the caller under "user"; reading "username" here
    # always missed and reported everyone as the built-in `elastic` superuser.
    username = str(user.get("user") or "elastic")
    return {
        "username": username,
        "has_all_requested": can_write,
        # Kibana 8.15 answers twelve cluster privileges and thirteen per
        # index — measured. mockdr answered six of each, so a client reading
        # `cluster.manage_pipeline` or `index[…].view_index_metadata` — which
        # the Security Solution does, to decide what to offer — got
        # `undefined` where a boolean belongs.
        "cluster": {
            "all": can_write,
            "manage": can_write,
            "manage_api_key": can_write,
            "manage_index_templates": can_write,
            "manage_ml": can_write,
            "manage_own_api_key": can_write,
            "manage_pipeline": can_write,
            "manage_security": can_write,
            "manage_transform": can_write,
            "monitor": True,
            "monitor_ml": True,
            "monitor_transform": True,
        },
        "index": {
            ".alerts-security.alerts-default": {
                "all": can_write,
                "create": can_write,
                "create_doc": can_write,
                "create_index": can_write,
                "delete": can_write,
                "delete_index": can_write,
                "index": can_write,
                "maintenance": can_write,
                "manage": can_write,
                "monitor": True,
                "read": True,
                "view_index_metadata": True,
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
    from application.es_rules import queries as rule_queries

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
        # Presence, not truthiness: `risk_score: 0` and `name: ""` are
        # supplied values. Rejecting them as "undefined" turned a rule the
        # client did send into one it appears to have omitted.
        missing = [f for f in required if entry.get(f) is None]
        if missing:
            results.append({"error": {
                "status_code": 400,
                "message": f'Invalid value "undefined" supplied to "{missing[0]}"',
                "rule_id": entry.get("rule_id"),
            }})
            continue
        # The single-rule route already refused a duplicate `rule_id`; this
        # one did not, so a bulk import run twice made a second rule under
        # an id that is meant to be unique — and answered as though it had
        # created it. Kibana reports the clash on that entry and creates
        # the rest.
        rule_id = entry.get("rule_id")
        if rule_id and rule_queries.get_rule_by_rule_id(str(rule_id)):
            results.append({"rule_id": rule_id, "error": {
                "status_code": 409,
                "message": f'rule_id: "{rule_id}" already exists',
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
    """Export rules as NDJSON, the format ``_import`` consumes.

    ``objects`` is required even when it is empty: a client that meant to
    export a selection and sent no body was handed every rule mockdr held.
    """
    import json

    if "objects" not in body:
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, "[request body]: objects: Required",
        ))
    objects = body.get("objects") or []
    wanted = [str(o.get("rule_id")) for o in objects if isinstance(o, dict)]
    by_rule_id = {
        str(r.get("rule_id")): r
        for r in rule_queries.find_rules(page=1, per_page=10_000)["data"]
    }
    # An empty selection exports nothing. Treating it as "everything" handed
    # a client that meant to export one rule the whole ruleset.
    selected = [by_rule_id[rule_id] for rule_id in wanted if rule_id in by_rule_id]
    missing = [{"rule_id": rule_id} for rule_id in wanted if rule_id not in by_rule_id]

    lines = [json.dumps(r) for r in selected]
    lines.append(json.dumps({
        "exported_count": len(selected),
        "exported_rules_count": len(selected),
        "missing_rules": missing,
        "missing_rules_count": len(missing),
        "exported_exception_list_count": 0,
        "exported_exception_list_item_count": 0,
        "missing_exception_list_item_count": 0,
        "missing_exception_list_items": [],
        "missing_exception_lists": [],
        "missing_exception_lists_count": 0,
        "exported_action_connector_count": 0,
        "missing_action_connection_count": 0,
        "missing_action_connections": [],
        "excluded_action_connection_count": 0,
        "excluded_action_connections": [],
    }))
    # NDJSON, not a JSON-encoded string: returning `str` made FastAPI
    # serialise it with escapes, so the caller received a quoted blob.
    return PlainTextResponse(
        "\n".join(lines) + "\n", media_type="application/ndjson",
    )


@router.post("/api/detection_engine/rules/_import", dependencies=[Depends(require_kbn_xsrf)])
async def import_rules(
    request: Request,
    overwrite: bool = Query(default=False),
    _: dict = Depends(require_es_write),
) -> dict:
    """Import rules from NDJSON, creating them.

    The body is a multipart upload in Kibana; this accepts the NDJSON directly
    as well, which is what a scripted client usually sends.

    An earlier version ignored the body entirely and reported
    ``success: true`` with ``success_count: 0``. A client could export its
    rules, import them into a fresh instance, be told it had worked, and find
    nothing there — the export/import round trip a migration test exists to
    prove was reporting a success it had not performed.
    """
    import json

    from application.es_rules import commands as rule_commands

    payload = _import_payload(await request.body(), request.headers.get("content-type", ""))

    errors: list[dict] = []
    success_count = 0
    rules_count = 0

    for line in payload.splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            entry = json.loads(text)
        except ValueError:
            rules_count += 1
            errors.append({
                "rule_id": "(unknown id)",
                "error": {"status_code": 400, "message": "Invalid JSON on line"},
            })
            continue
        if not isinstance(entry, dict):
            continue
        # `_export` ends with a summary line. It is not a rule, and Kibana's
        # importer skips it rather than counting it as a failure.
        if "exported_count" in entry or "rules_count" in entry:
            continue

        rules_count += 1
        rule_id = str(entry.get("rule_id") or "")
        existing = es_rule_repo.get_by_rule_id(rule_id) if rule_id else None

        if existing and not overwrite:
            errors.append({
                "rule_id": rule_id,
                "error": {
                    "status_code": 409,
                    "message": f'rule_id: "{rule_id}" already exists',
                },
            })
            continue

        if existing is not None:
            rule_commands.update_rule(existing, entry)
        else:
            rule_commands.create_rule(entry)
        success_count += 1

    return {
        "success": not errors,
        "success_count": success_count,
        "rules_count": rules_count,
        "errors": errors,
        "exceptions_errors": [],
        "exceptions_success": True,
        "exceptions_success_count": 0,
        "action_connectors_success": True,
        "action_connectors_success_count": 0,
        "action_connectors_errors": [],
        "action_connectors_warnings": [],
    }


def _import_payload(body: bytes, content_type: str) -> str:
    """Return the NDJSON from an import body, multipart or raw.

    Kibana's UI posts the file as ``multipart/form-data``; scripted clients
    usually POST the NDJSON directly. Both have to work, so the multipart
    wrapper is stripped when it is there and the body used as-is when it
    is not.
    """
    text = body.decode("utf-8", errors="replace")
    if "multipart/form-data" not in content_type.lower():
        return text

    boundary = ""
    for part in content_type.split(";"):
        name, _, value = part.strip().partition("=")
        if name.lower() == "boundary":
            boundary = value.strip('"')
    if not boundary:
        return text

    lines: list[str] = []
    for section in text.split(f"--{boundary}"):
        head, sep, payload = section.partition("\r\n\r\n")
        if not sep:
            head, sep, payload = section.partition("\n\n")
        if sep and "content-disposition" in head.lower():
            lines.append(payload.rstrip("-\r\n"))
    return "\n".join(lines)


# ── Cases ────────────────────────────────────────────────────────────────────


@router.get(
    "/api/cases/status",
    dependencies=[refuses_unknown("owner", dialect=INVALID_KEYS)],
)
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


@router.get(
    "/api/cases/reporters",
    dependencies=[refuses_unknown("owner", dialect=INVALID_KEYS)],
)
def case_reporters(
    _: dict = Depends(require_es_auth),
) -> list[dict]:
    """Every distinct case author, which the UI offers as a filter."""
    seen: dict[str, dict] = {}
    for case in case_queries.find_cases(page=1, per_page=10_000)["cases"]:
        author = case.get("created_by") or {}
        username = str(author.get("username", ""))
        if username and username not in seen:
            reporter = {
                "username": username,
                "full_name": author.get("full_name"),
                "email": author.get("email"),
            }
            # Kibana 8.15 carries `profile_uid` only for an author that has
            # one; it is absent otherwise, not null — measured. A client
            # asking whether the key is there was told yes, always.
            if author.get("profile_uid"):
                reporter["profile_uid"] = author["profile_uid"]
            seen[username] = reporter
    return sorted(seen.values(), key=lambda r: str(r["username"]))


@router.post("/internal/cases/_bulk_get", dependencies=[Depends(require_kbn_xsrf)])
def bulk_get_cases(
    body: dict = Body(...),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Fetch several cases by id.

    Kibana reports the ones it could not resolve in ``errors`` rather than
    failing the request, and names them the way the saved-objects layer
    underneath does — ``Saved object [cases/<id>] not found``, not the case
    id on its own.

    This is one of the routes Kibana keeps under ``/internal``: ``/api`` has
    no ``_bulk_get`` and answers 404, so serving it there let a client
    succeed against the mock on a path the product does not have.
    """
    ids = body.get("ids")
    if ids is None:
        raise HTTPException(
            status_code=400,
            detail=build_kbn_error_response(
                400, 'Invalid value "undefined" supplied to "ids"'),
        )
    if not isinstance(ids, list):
        # Kibana joins `ids` before validating its type, so a string body
        # crashes the route rather than being rejected. Measured on 8.15;
        # a client that branches on 5xx must see the same thing here.
        raise HTTPException(
            status_code=500,
            detail=build_kbn_error_response(500, "ids.join is not a function"),
        )
    if not ids:
        raise HTTPException(
            status_code=400,
            detail=build_kbn_error_response(
                400,
                "The length of the field ids is too short. "
                "Array must be of length >= 1.",
            ),
        )
    for candidate in ids:
        if not isinstance(candidate, str):
            raise HTTPException(
                status_code=400,
                detail=build_kbn_error_response(
                    400, f'Invalid value "{candidate}" supplied to "ids"'),
            )

    cases: list[dict] = []
    errors: list[dict] = []
    for case_id in ids:
        found = case_queries.get_case(case_id)
        if found is None:
            errors.append({
                "error": "Not Found",
                "message": f"Saved object [cases/{case_id}] not found",
                "status": 404,
                "caseId": case_id,
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
    """Summarise an exception list's items by operating system.

    ``list_id`` identifies what to summarise, so a request without one has
    nothing to answer. Returning all-zero counts with a 200 was indistinguishable
    from a list that genuinely has no items.
    """
    if not list_id:
        raise HTTPException(
            status_code=400,
            # Kibana's own wording, which the two exception-list routes
            # beside this one already used: measured on 8.15.
            detail=build_security_solution_error(400, "id or list_id required"),
        )
    try:
        items = exception_queries.find_items(
            list_id=list_id, page=1, per_page=10_000,
        )["data"]
    except exception_queries.ExceptionListNotFoundError as exc:
        # The list route answers 404 for a list that is not there; this one
        # let the exception out and became a plain-text 500. A well-formed id
        # that resolves to nothing is the commonest thing a client sends.
        raise HTTPException(
            status_code=404, detail=build_security_solution_error(404, str(exc)),
        ) from exc

    counts = {"windows": 0, "linux": 0, "macos": 0}
    for item in items:
        for os_type in item.get("os_types") or []:
            if os_type in counts:
                counts[os_type] += 1
    return {**counts, "total": len(items)}


# ── Endpoint ─────────────────────────────────────────────────────────────────


@router.get("/api/endpoint/action_status")
def endpoint_action_status(
    request: Request,
    agent_ids: str = Query(default="", alias="agent_ids"),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Report how many actions are still pending per agent.

    `agent_ids` is required: without it Kibana refuses the request, where
    mockdr answered with an empty list — which reads as "nothing pending".
    """
    try:
        validate_config_schema(
            {k: request.query_params.getlist(k) for k in request.query_params},
            ENDPOINT_ACTION_STATUS_QUERY, where="request query", from_query=True,
        )
    except ConfigSchemaError as exc:
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, str(exc),
        )) from exc
    wanted = [a.strip() for a in agent_ids.split(",") if a.strip()]

    data = []
    for agent_id in wanted:
        # Counted per action, as Kibana reports it. Filing every pending
        # action under "isolate" told a client an endpoint was awaiting
        # isolation when what it was actually awaiting was a kill-process.
        pending: Counter[str] = Counter(
            str(a.get("action") or "isolate")
            for a in endpoint_commands.list_actions(agent_id)
            if a.get("status") == "pending"
        )
        data.append({"agent_id": agent_id, "pending_actions": dict(pending)})
    return {"data": data}


#: How Kibana's route schema names a query member it wanted and did not get.
_QUERY_REQUIRED = "[request query.{name}]: expected value of type [string] but got [undefined]"


@router.get("/api/endpoint/action_log/{agent_id}")
def endpoint_action_log(
    agent_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=1000),
    start_date: str = Query(default=""),
    end_date: str = Query(default=""),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Return the actions run against one endpoint, newest first.

    The window is not optional: 8.15 refuses a request without `start_date`,
    and then without `end_date`, naming each in turn — measured. mockdr
    answered an empty log instead, so a client that had forgotten the window
    was told the endpoint had done nothing.
    """
    for name, value in (("start_date", start_date), ("end_date", end_date)):
        if not value:
            raise HTTPException(status_code=400, detail=build_kbn_error_response(
                400, _QUERY_REQUIRED.format(name=name),
            ))
    # Repository order is insertion order, so serving it unsorted put the
    # *oldest* action on page 1 — the reverse of what this endpoint promises,
    # and the reverse of what an operator checking "what just happened" needs.
    actions = sorted(
        endpoint_commands.list_actions(agent_id),
        key=lambda a: str(a.get("started_at") or ""),
        reverse=True,
    )
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
    """Report the endpoint's last policy application.

    The endpoint is named by `agentId`, and a request without one is refused
    by the route's schema before anything is looked up — measured. mockdr
    answered `Endpoint  not found`, which says an endpoint with no name does
    not exist rather than that the caller did not name one.
    """
    if not agent_id:
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, _QUERY_REQUIRED.format(name="agentId"),
        ))
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


#: The only suggestion type this route takes — measured on 8.15, which
#: refuses every other name including Kibana's own `trustedApps`.
_SUGGESTION_TYPE = "eventFilters"


@router.post(
    "/api/endpoint/suggestions/{suggestion_type}",
    dependencies=[Depends(require_kbn_xsrf)],
)
def endpoint_suggestions(
    suggestion_type: str,
    body: dict = Body(default={}),
    _: dict = Depends(require_es_auth),
) -> list[str]:
    """Suggest values for a field, which the UI uses for autocomplete.

    The Endpoint routes validate with @kbn/config-schema, which names the
    member in the bracket and reports the type it wanted. Three things were
    unchecked: `suggestion_type`, which has exactly one legal value and was
    read by nothing at all — every name answered the same list — and the two
    body members, without which there is nothing to suggest values for.
    """
    if suggestion_type != _SUGGESTION_TYPE:
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400,
            "[request params.suggestion_type]: expected value to equal "
            f"[{_SUGGESTION_TYPE}]",
        ))
    field = body.get("field", body.get("fieldName"))
    if not isinstance(field, str):
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400,
            "[request body.field]: expected value of type [string] "
            f"but got [{'undefined' if field is None else type(field).__name__}]",
        ))
    query = body.get("query")
    if not isinstance(query, str):
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400,
            "[request body.query]: expected value of type [string] "
            f"but got [{'undefined' if query is None else type(query).__name__}]",
        ))
    entries = endpoint_queries.list_endpoints(page=1, per_page=10_000).get("data", [])


    values: set[str] = set()
    for entry in entries:
        host = entry.get("metadata", {}).get("host", {})
        if field.endswith("os.name"):
            values.add(str(host.get("os", {}).get("name", "")))
        else:
            values.add(str(host.get("hostname", "")))
    return sorted(v for v in values if v)
