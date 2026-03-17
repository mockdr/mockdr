"""Elastic Security Endpoint API router.

Implements Kibana Security endpoint management endpoints: metadata listing,
detail, and response actions (isolate, unisolate, kill process, scan).
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from api.es_auth import require_es_auth, require_es_write, require_kbn_xsrf
from application.es_endpoints import commands as endpoint_commands
from application.es_endpoints import queries as endpoint_queries
from utils.es_response import build_es_error_response

router = APIRouter(tags=["Elastic Endpoints"])


# ── Metadata ─────────────────────────────────────────────────────────────────


@router.get("/api/endpoint/metadata")
def list_endpoints(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=1000),
    hostname: str = Query(None),
    host_os_name: str = Query(None),
    agent_status: str = Query(None),
    policy_id: str = Query(None),
    _: dict = Depends(require_es_auth),
) -> dict:
    """List all managed endpoints with optional filtering."""
    return endpoint_queries.list_endpoints(
        page=page,
        per_page=per_page,
        hostname=hostname,
        host_os_name=host_os_name,
        agent_status=agent_status,
        policy_id=policy_id,
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
            detail=build_es_error_response(404, "not_found", f"Endpoint {agent_id} not found"),
        )
    return result


# ── Response Actions ─────────────────────────────────────────────────────────


@router.post("/api/endpoint/action/isolate", dependencies=[Depends(require_kbn_xsrf)])
def isolate_endpoint(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Isolate an endpoint from the network."""
    ids = body.get("endpoint_ids") or []
    agent_id = ids[0] if ids else body.get("agent_id")
    if not agent_id:
        raise HTTPException(
            status_code=400,
            detail=build_es_error_response(400, "bad_request", "endpoint_ids is required"),
        )
    comment = body.get("comment", "")
    result = endpoint_commands.isolate_endpoint(agent_id, comment)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_es_error_response(404, "not_found", f"Endpoint {agent_id} not found"),
        )
    return result


@router.post("/api/endpoint/action/unisolate", dependencies=[Depends(require_kbn_xsrf)])
def unisolate_endpoint(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Release an endpoint from network isolation."""
    ids = body.get("endpoint_ids") or []
    agent_id = ids[0] if ids else body.get("agent_id")
    if not agent_id:
        raise HTTPException(
            status_code=400,
            detail=build_es_error_response(400, "bad_request", "endpoint_ids is required"),
        )
    comment = body.get("comment", "")
    result = endpoint_commands.unisolate_endpoint(agent_id, comment)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_es_error_response(404, "not_found", f"Endpoint {agent_id} not found"),
        )
    return result


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
            detail=build_es_error_response(400, "bad_request", "endpoint_ids is required"),
        )
    params = body.get("parameters", {})
    result = endpoint_commands.kill_process(agent_id, params)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_es_error_response(404, "not_found", f"Endpoint {agent_id} not found"),
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
            detail=build_es_error_response(400, "bad_request", "endpoint_ids is required"),
        )
    comment = body.get("comment", "")
    result = endpoint_commands.scan_endpoint(agent_id, comment)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_es_error_response(404, "not_found", f"Endpoint {agent_id} not found"),
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
            detail=build_es_error_response(404, "not_found", f"Action {action_id} not found"),
        )
    return result
