"""Cortex XDR Endpoints API router.

All endpoints use POST with ``{"request_data": {...}}`` body wrapper.
Responses use ``{"reply": {...}}`` envelope via ``build_xdr_*`` helpers.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException

from api.xdr_auth import require_xdr_auth, require_xdr_write
from application.xdr_endpoints import commands as endpoint_commands
from application.xdr_endpoints import queries as endpoint_queries
from utils.xdr_response import build_xdr_error

router = APIRouter(tags=["XDR Endpoints"])


@router.post("/endpoints/get_endpoint/")
def get_endpoints(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """List endpoints with optional filtering and pagination."""
    request_data = body.get("request_data", {})
    return endpoint_queries.get_endpoints(request_data)


@router.post("/endpoints/isolate")
def isolate_endpoint(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Isolate an endpoint from the network."""
    request_data = body.get("request_data", {})
    endpoint_id = request_data.get("endpoint_id", "")
    result = endpoint_commands.isolate_endpoint(endpoint_id)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, f"Endpoint {endpoint_id} not found"),
        )
    return result


@router.post("/endpoints/unisolate")
def unisolate_endpoint(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Release an endpoint from network isolation."""
    request_data = body.get("request_data", {})
    endpoint_id = request_data.get("endpoint_id", "")
    result = endpoint_commands.unisolate_endpoint(endpoint_id)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, f"Endpoint {endpoint_id} not found"),
        )
    return result


@router.post("/endpoints/scan/")
def scan_endpoint(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Initiate a scan on an endpoint."""
    request_data = body.get("request_data", {})
    endpoint_id = request_data.get("endpoint_id", "")
    result = endpoint_commands.scan_endpoint(endpoint_id)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, f"Endpoint {endpoint_id} not found"),
        )
    return result


@router.post("/endpoints/delete/")
def delete_endpoints(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Delete one or more endpoints."""
    request_data = body.get("request_data", {})
    endpoint_ids = request_data.get("endpoint_id_list", [])
    return endpoint_commands.delete_endpoints(endpoint_ids)


@router.post("/endpoints/get_policy/")
def get_policy(
    body: dict = Body(...),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Get the policy applied to an endpoint."""
    request_data = body.get("request_data", {})
    endpoint_id = request_data.get("endpoint_id", "")
    result = endpoint_queries.get_policy(endpoint_id)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, f"Endpoint {endpoint_id} not found"),
        )
    return result


@router.post("/endpoints/update_agent_name/")
def update_agent_name(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Update the alias (display name) of an endpoint."""
    request_data = body.get("request_data", {})
    endpoint_id = request_data.get("endpoint_id", "")
    alias = request_data.get("alias", "")
    result = endpoint_commands.update_agent_name(endpoint_id, alias)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, f"Endpoint {endpoint_id} not found"),
        )
    return result


@router.post("/endpoints/terminate_process/")
def terminate_process(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Terminate a process on an endpoint."""
    request_data = body.get("request_data", {})
    endpoint_id = request_data.get("endpoint_id", "")
    result = endpoint_commands.terminate_process(endpoint_id, request_data)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, f"Endpoint {endpoint_id} not found"),
        )
    return result


@router.post("/endpoints/quarantine/")
def quarantine_file(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Quarantine a file on an endpoint."""
    request_data = body.get("request_data", {})
    endpoint_id = request_data.get("endpoint_id", "")
    result = endpoint_commands.quarantine_file(endpoint_id, request_data)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, f"Endpoint {endpoint_id} not found"),
        )
    return result


@router.post("/endpoints/restore/")
def restore_file(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Restore a quarantined file on an endpoint."""
    request_data = body.get("request_data", {})
    endpoint_id = request_data.get("endpoint_id", "")
    result = endpoint_commands.restore_file(endpoint_id, request_data)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, f"Endpoint {endpoint_id} not found"),
        )
    return result


@router.post("/endpoints/file_retrieval/")
def file_retrieval(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Retrieve a file from an endpoint."""
    request_data = body.get("request_data", {})
    endpoint_id = request_data.get("endpoint_id", "")
    result = endpoint_commands.file_retrieval(endpoint_id, request_data)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, f"Endpoint {endpoint_id} not found"),
        )
    return result
