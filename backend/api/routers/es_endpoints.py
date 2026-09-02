"""Elastic Security Endpoint API router.

Implements Kibana Security endpoint management endpoints: metadata listing,
detail, and response actions (isolate, unisolate, kill process, scan).
"""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, Response

from api.es_auth import require_es_auth, require_es_write, require_kbn_xsrf
from application.es_endpoints import commands as endpoint_commands
from application.es_endpoints import queries as endpoint_queries
from utils.es_response import build_kbn_error_response, build_security_solution_error
from utils.kibana_query import refuses_unknown
from utils.kibana_validation import (
    ENDPOINT_ACTION_BODY,
    ENDPOINT_METADATA_QUERY,
    ConfigSchemaError,
    SchemaField,
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
    _action_body(body, "isolate")
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


@router.post("/api/endpoint/unisolate", dependencies=[Depends(require_kbn_xsrf)],
             status_code=308)
def unisolate_legacy_path(request: Request) -> Response:
    """The older path, which Kibana answers with a permanent redirect.

    Measured against Kibana 8.15: `POST /api/endpoint/unisolate` answers 308
    with `location: /api/endpoint/action/unisolate` and no body, while
    `/api/endpoint/isolate` beside it is served directly -- the pair is not
    symmetric, and this mock served both the same way. A client that follows
    redirects cannot tell; one that does not saw a 404 here and a 308 there.
    """
    # Kibana is the root of its own deployment and answers a root-relative
    # location; this mock is mounted under `/kibana`, so the target is built
    # from the path the request arrived on rather than written down -- a
    # location of `/api/...` would send a client configured with the mount
    # prefix to somewhere that does not exist.
    target = request.url.path.replace(
        "/api/endpoint/unisolate", "/api/endpoint/action/unisolate", 1)
    return Response(status_code=308, headers={"location": target})


@router.post("/api/endpoint/action/unisolate", dependencies=[Depends(require_kbn_xsrf)])
def unisolate_endpoint(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Release an endpoint from network isolation."""
    _action_body(body, "unisolate")
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
    return _record_action(body, "kill-process", _action_body(body, "kill_process"))


@router.post("/api/endpoint/action/scan", dependencies=[Depends(require_kbn_xsrf)])
def scan_endpoint(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Trigger a scan on an endpoint."""
    return _record_action(body, "scan", _action_body(body, "scan"))


# Kibana 8.15 routes seven more response actions than mockdr served, and a
# playbook that ran any of the four below met a 404 from a product that has
# the route. The command names are Kibana's own, hyphenated — the vocabulary
# its `commands` filter validates against (measured: isolate, unisolate,
# kill-process, suspend-process, running-processes, get-file, execute,
# upload, scan). `upload` is the one left out: it takes a multipart body and
# a file, which this mock has nowhere to put.


def _record_action(body: dict, command: str, params: dict) -> dict:
    """Record one response action against the endpoint the body names.

    Raises:
        HTTPException: 400 for a body Kibana's schema refuses, 404 for an
            endpoint this install does not have.
    """
    ids = body.get("endpoint_ids") or []
    agent_id = ids[0] if ids else body.get("agent_id")
    if not agent_id:
        raise HTTPException(
            status_code=400,
            detail=build_kbn_error_response(400, _NO_ENDPOINT_IDS),
        )
    result = endpoint_commands.run_action(
        agent_id, command, body.get("comment", ""), params,
    )
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_security_solution_error(404, f"Endpoint {agent_id} not found"),
        )
    return result


@router.post("/api/endpoint/action/suspend_process", dependencies=[Depends(require_kbn_xsrf)])
def suspend_process(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Suspend a process on an endpoint."""
    return _record_action(body, "suspend-process", _action_body(body, "suspend_process"))


@router.post("/api/endpoint/action/running_procs", dependencies=[Depends(require_kbn_xsrf)])
def running_processes(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """List the processes running on an endpoint.

    The one response action that asks for no `parameters` block: 8.15 takes
    a body with nothing but `endpoint_ids` here (measured).
    """
    return _record_action(body, "running-processes", _action_body(body, "running_procs"))


@router.post("/api/endpoint/action/get_file", dependencies=[Depends(require_kbn_xsrf)])
def get_file(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Fetch a file from an endpoint."""
    return _record_action(body, "get-file", _action_body(body, "get_file"))


@router.post("/api/endpoint/action/execute", dependencies=[Depends(require_kbn_xsrf)])
def execute_command(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Run a command on an endpoint."""
    return _record_action(body, "execute", _action_body(body, "execute"))


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
#: What each action's `parameters` block declares, measured member by member
#: on 8.15. An action not named here declares none, so any member inside its
#: block is one the schema has no definition for — which is what `isolate`
#: answers to a `parameters: {path: …}`.
_ACTION_PARAMETERS: dict[str, tuple[SchemaField, ...]] = {
    "scan": (SchemaField("path", required=True),),
    "get_file": (SchemaField("path", required=True),),
    "execute": (
        SchemaField("command", required=True),
        SchemaField("timeout", "number"),
    ),
}

#: The two actions whose block is a *union*: one arm names a process by `pid`,
#: the other by `entity_id`. Kibana tries both and reports the first failure
#: of each, numbered — so a block naming neither reads as two failures, not
#: one, and a block naming a member no arm declares fails on that instead.
_PROCESS_ARMS: tuple[tuple[SchemaField, ...], ...] = (
    (SchemaField("pid", "number", required=True),),
    (SchemaField("entity_id", required=True),),
)
_PROCESS_ACTIONS = ("kill_process", "suspend_process")

#: What a union action answers to no block at all. The others do not have a
#: case of their own for it: 8.15 reports the member *inside* the block it
#: wanted, exactly as it does for a block that is there and incomplete.
_PARAMETERS_REQUIRED = (
    "[request body.parameters]: expected at least one defined value but got [undefined]"
)


def _require_parameters(body: dict, action: str) -> dict:
    """The `parameters` block an action needs, refused as Kibana refuses it.

    Raises:
        HTTPException: 400, in Kibana's own wording.
    """
    params = body.get("parameters")
    if not isinstance(params, dict):
        params = {}
    if action in _PROCESS_ACTIONS:
        if "parameters" not in body:
            raise HTTPException(status_code=400, detail=build_kbn_error_response(
                400, _PARAMETERS_REQUIRED,
            ))
        _require_one_arm(params)
        return params
    try:
        validate_config_schema(
            params, _ACTION_PARAMETERS.get(action, ()), where="request body.parameters",
        )
    except ConfigSchemaError as exc:
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, str(exc),
        )) from exc
    return params


def _require_one_arm(params: dict) -> None:
    """Refuse a process block that satisfies neither arm of the union.

    Raises:
        HTTPException: 400, listing what each arm complained about.
    """
    failures = []
    for index, arm in enumerate(_PROCESS_ARMS):
        try:
            validate_config_schema(
                params, arm, where=f"request body.parameters.{index}",
            )
        except ConfigSchemaError as exc:
            failures.append(f"- {exc}")
    if len(failures) == len(_PROCESS_ARMS):
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, "[request body.parameters]: types that failed validation:\n"
                 + "\n".join(failures),
        ))


def _validate_action_body(
    body: dict,
    fields: tuple[SchemaField, ...] = ENDPOINT_ACTION_BODY,
    *,
    undeclared: bool = True,
) -> None:
    """Refuse a response-action body the way Kibana's schema refuses it.

    mockdr looked for an id and reported "Endpoint x not found" for anything
    else, so a body with a member Kibana has no definition for came back as a
    404 about an endpoint rather than a 400 about the request.

    `undeclared` splits the check in two because 8.15 asks in this order: the
    members it declares, then the action's own `parameters` block, then the
    members it does not declare. A body missing `parameters` *and* carrying
    an unknown key is refused for the `parameters` (measured on all six
    actions that take one).
    """
    try:
        validate_config_schema(
            body, fields, where="request body", undeclared=undeclared,
        )
    except ConfigSchemaError as exc:
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, str(exc),
        )) from exc


#: `ENDPOINT_ACTION_BODY` split where `parameters` sits, because 8.15 checks
#: that block *in its declared position*: a body with a bad `agent_type` and
#: no `parameters` is refused for the `parameters`, and one with a good
#: `parameters` and a bad `agent_type` for the `agent_type` (measured).
_PARAMETERS_AT = next(
    i for i, field in enumerate(ENDPOINT_ACTION_BODY) if field.name == "parameters"
)
_BODY_BEFORE_PARAMETERS = ENDPOINT_ACTION_BODY[:_PARAMETERS_AT]
_BODY_AFTER_PARAMETERS = ENDPOINT_ACTION_BODY[_PARAMETERS_AT + 1:]


def _action_body(body: dict, action: str) -> dict:
    """Check a response-action body in the order 8.15 checks it.

    The members it declares, in declaration order, with the action's own
    `parameters` block checked where that block is declared — and the
    members it does *not* declare last of all.

    Returns:
        The `parameters` block, empty for an action that declares none.
    """
    _validate_action_body(body, _BODY_BEFORE_PARAMETERS, undeclared=False)
    params = _require_parameters(body, action)
    _validate_action_body(body, _BODY_AFTER_PARAMETERS, undeclared=False)
    _validate_action_body(body, ENDPOINT_ACTION_BODY)
    return params
