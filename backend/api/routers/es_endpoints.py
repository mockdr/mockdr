"""Elastic Security Endpoint API router.

Implements Kibana Security endpoint management endpoints: metadata listing,
detail, and response actions (isolate, unisolate, kill process, scan).
"""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request

from api.es_auth import require_es_auth, require_es_write, require_kbn_xsrf
from application.es_endpoints import commands as endpoint_commands
from application.es_endpoints import queries as endpoint_queries
from utils.es_response import build_kbn_error_response, build_security_solution_error
from utils.kibana_query import refuses_unknown
from utils.kibana_validation import (
    ENDPOINT_ACTION_BODY,
    ENDPOINT_METADATA_QUERY,
    ConfigSchemaError,
    validate_config_schema,
)

#: Kibana's config-schema wording for a missing array (measured on 8.15).
_NO_ENDPOINT_IDS = "[request body.endpoint_ids]: expected value of type [array] but got [undefined]"

router = APIRouter(tags=["Elastic Endpoints"])


# ── Metadata ─────────────────────────────────────────────────────────────────


@router.get("/api/endpoint/metadata")
def list_endpoints(
    request: Request,
    # Untyped on purpose: FastAPI's own 422 would pre-empt the wording this
    # schema answers with.
    page: str = Query("0"),
    page_size: str = Query("10", alias="pageSize"),
    _: dict = Depends(require_es_auth),
) -> dict:
    """List all managed endpoints.

    The query is validated against Kibana's own schema, which is a fourth
    dialect again (@kbn/config-schema): it names the member in the bracket,
    stops at the first failure, and refuses a key it has no definition for.
    mockdr took four filters Kibana does not declare and a `per_page` it
    spells `pageSize`, so a client written here sent a query the real one
    refuses.

    `page` counts from 0, which is what its schema minimum says; whether the
    first page is 0 or 1 cannot be checked against a Basic licence, because
    the endpoint list needs Enterprise before it returns any data.
    """
    try:
        validate_config_schema(
            request.query_params, ENDPOINT_METADATA_QUERY,
            where="request query", from_query=True,
        )
    except ConfigSchemaError as exc:
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, str(exc),
        )) from exc
    return endpoint_queries.list_endpoints(
        # The page counts from 0 here and is echoed back as it was asked
        # for; mockdr answered with the number after it.
        page=int(float(page)) + 1,
        per_page=int(float(page_size)),
        sort_field=request.query_params.get("sortField", "enrolled_at"),
        sort_direction=request.query_params.get("sortDirection", "desc"),
    ) | {"page": int(float(page))}


@router.get("/api/endpoint/metadata/{agent_id}")
def get_endpoint(
    agent_id: str,
    _: dict = Depends(require_es_auth),
) -> dict:
    """Get a single endpoint by agent ID."""
    result = endpoint_queries.get_endpoint(agent_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            # Kibana's endpoint routes answer in Boom, with this wording (measured on 8.15).
            detail=build_kbn_error_response(404, f"Endpoint with id {agent_id} not found"),
        )
    return result


# ── Response Actions ─────────────────────────────────────────────────────────


@router.post("/api/endpoint/isolate", dependencies=[Depends(require_kbn_xsrf)])
@router.post("/api/endpoint/action/isolate", dependencies=[Depends(require_kbn_xsrf)])
def isolate_endpoint(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Isolate an endpoint from the network."""
    _validate_action_body(body)
    ids = body.get("endpoint_ids") or []
    agent_id = ids[0] if ids else body.get("agent_id")
    if not agent_id:
        raise HTTPException(
            status_code=400,
            detail=build_kbn_error_response(400, _NO_ENDPOINT_IDS),
        )
    comment = body.get("comment", "")
    result = endpoint_commands.isolate_endpoint(agent_id, comment)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_security_solution_error(404, f"Endpoint {agent_id} not found"),
        )
    return result


@router.post("/api/endpoint/unisolate", dependencies=[Depends(require_kbn_xsrf)])
@router.post("/api/endpoint/action/unisolate", dependencies=[Depends(require_kbn_xsrf)])
def unisolate_endpoint(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Release an endpoint from network isolation."""
    _validate_action_body(body)
    ids = body.get("endpoint_ids") or []
    agent_id = ids[0] if ids else body.get("agent_id")
    if not agent_id:
        raise HTTPException(
            status_code=400,
            detail=build_kbn_error_response(400, _NO_ENDPOINT_IDS),
        )
    comment = body.get("comment", "")
    result = endpoint_commands.unisolate_endpoint(agent_id, comment)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_security_solution_error(404, f"Endpoint {agent_id} not found"),
        )
    return result


# Kibana 8.15 serves the response actions under `/api/endpoint/action/…`
# and answers 404 for the bare `/api/endpoint/kill_process` and
# `/api/endpoint/scan` — measured, along with `suspend_process`,
# `running_procs`, `get_file` and `execute`. Only `isolate` is served under
# both spellings. Serving the short forms let a client build against paths
# the product does not have.
@router.post("/api/endpoint/action/kill_process", dependencies=[Depends(require_kbn_xsrf)])
def kill_process(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Kill a process on an endpoint."""
    ids = body.get("endpoint_ids") or []
    agent_id = ids[0] if ids else body.get("agent_id")
    if not agent_id:
        raise HTTPException(
            status_code=400,
            detail=build_kbn_error_response(400, _NO_ENDPOINT_IDS),
        )
    params = _require_parameters(body, "kill_process")
    result = endpoint_commands.kill_process(agent_id, params)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_security_solution_error(404, f"Endpoint {agent_id} not found"),
        )
    return result


@router.post("/api/endpoint/action/scan", dependencies=[Depends(require_kbn_xsrf)])
def scan_endpoint(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Trigger a scan on an endpoint."""
    ids = body.get("endpoint_ids") or []
    agent_id = ids[0] if ids else body.get("agent_id")
    if not agent_id:
        raise HTTPException(
            status_code=400,
            detail=build_kbn_error_response(400, _NO_ENDPOINT_IDS),
        )
    _require_parameters(body, "scan")
    comment = body.get("comment", "")
    result = endpoint_commands.scan_endpoint(agent_id, comment)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_security_solution_error(404, f"Endpoint {agent_id} not found"),
        )
    return result


# ── Action Status ────────────────────────────────────────────────────────────


@router.get(
    "/api/endpoint/action",
    dependencies=[refuses_unknown(
        "agentIds", "page", "pageSize", "startDate", "endDate", "userIds",
        "withOutputs", "commands", "statuses", "types", "agentTypes",
    )],
)
def list_actions(
    agent_ids: list[str] = Query(default=[], alias="agentIds"),
    _: dict = Depends(require_es_auth),
) -> dict:
    """List endpoint action responses, optionally filtered by agent.

    8.15 spells the filter `agentIds`, and refuses `agent_id` outright:
    `[request query.agent_id]: definition for this key is missing` — measured,
    the schema is checked before the endpoint authorisation that otherwise
    answers this route. mockdr took the snake_case spelling, so a client that
    filtered here saw its filter work against the mock and 400 in production.
    """
    agent_id = agent_ids[0] if agent_ids else None
    actions = endpoint_commands.list_actions(agent_id)
    return {"data": actions, "total": len(actions), "page": 1, "per_page": len(actions) or 20}


@router.get("/api/endpoint/action/{action_id}")
def get_action(
    action_id: str,
    _: dict = Depends(require_es_auth),
) -> dict:
    """Get a single action response by ID."""
    result = endpoint_commands.get_action(action_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_kbn_error_response(404, f"Action with id '{action_id}' not found."),
        )
    return result


#: What each response action requires inside `parameters`, and how Kibana
#: says so. Measured on 8.15: `scan` and `get_file` name a `path`, `execute`
#: a `command`, and the two process actions ask only that the block carry
#: something. mockdr accepted a scan with no parameters at all and answered
#: 200, so a client that had forgotten the one member the action is about
#: was told the scan had started.
_ACTION_PARAMETERS = {
    "scan": ("path", "[request body.parameters.path]: expected value of type "
                     "[string] but got [undefined]"),
    "get_file": ("path", "[request body.parameters.path]: expected value of type "
                         "[string] but got [undefined]"),
    "execute": ("command", "[request body.parameters.command]: expected value of type "
                           "[string] but got [undefined]"),
}
_PARAMETERS_REQUIRED = (
    "[request body.parameters]: expected at least one defined value but got [undefined]"
)


def _require_parameters(body: dict, action: str) -> dict:
    """The `parameters` block an action needs, refused the way Kibana refuses it.

    Raises:
        HTTPException: 400, in Kibana's own wording.
    """
    params = body.get("parameters")
    if not isinstance(params, dict):
        params = {}
    # An action with a member of its own names that member whether the block
    # is absent or merely incomplete; the two process actions ask only that
    # the block carry something. Measured on 8.15.
    named = _ACTION_PARAMETERS.get(action)
    if named:
        if not params.get(named[0]):
            raise HTTPException(status_code=400, detail=build_kbn_error_response(400, named[1]))
        return params
    if not params:
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, _PARAMETERS_REQUIRED,
        ))
    return params


def _validate_action_body(body: dict) -> None:
    """Refuse a response-action body the way Kibana's schema refuses it.

    mockdr looked for an id and reported "Endpoint x not found" for anything
    else, so a body with a member Kibana has no definition for came back as a
    404 about an endpoint rather than a 400 about the request.
    """
    try:
        validate_config_schema(body, ENDPOINT_ACTION_BODY, where="request body")
    except ConfigSchemaError as exc:
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, str(exc),
        )) from exc
