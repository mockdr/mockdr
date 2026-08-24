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
        page=int(float(page)) + 1, per_page=int(float(page_size)),
    )


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


@router.post("/api/endpoint/kill_process", dependencies=[Depends(require_kbn_xsrf)])
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
    params = body.get("parameters", {})
    result = endpoint_commands.kill_process(agent_id, params)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_security_solution_error(404, f"Endpoint {agent_id} not found"),
        )
    return result


@router.post("/api/endpoint/scan", dependencies=[Depends(require_kbn_xsrf)])
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
    comment = body.get("comment", "")
    result = endpoint_commands.scan_endpoint(agent_id, comment)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_security_solution_error(404, f"Endpoint {agent_id} not found"),
        )
    return result


# ── Action Status ────────────────────────────────────────────────────────────


@router.get("/api/endpoint/action")
def list_actions(
    agent_id: str = Query(None),
    _: dict = Depends(require_es_auth),
) -> dict:
    """List endpoint action responses, optionally filtered by agent ID."""
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
