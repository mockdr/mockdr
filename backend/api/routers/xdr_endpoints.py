"""Cortex XDR Endpoints API router.

All endpoints use POST with ``{"request_data": {...}}`` body wrapper.
Responses use ``{"reply": {...}}`` envelope via ``build_xdr_*`` helpers.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException

from api.xdr_auth import require_xdr_auth, require_xdr_write
from application.xdr_endpoints import commands as endpoint_commands
from application.xdr_endpoints import queries as endpoint_queries
from utils.xdr_fixtures import xdr_shape
from utils.xdr_response import XDR_ERR_INTERNAL, build_xdr_error, require_request_data

router = APIRouter(tags=["XDR Endpoints"])


@router.post("/endpoints/get_endpoint/")
@xdr_shape("endpoints_get_endpoint")
def get_endpoints(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """List endpoints with optional filtering and pagination."""
    request_data = require_request_data(body)
    return endpoint_queries.get_endpoints(request_data)


@router.post("/endpoints/isolate")
@xdr_shape("endpoints_isolate")
def isolate_endpoint(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Isolate an endpoint from the network."""
    request_data = require_request_data(body)
    targets = endpoint_commands.endpoints_named_by(request_data)
    result = endpoint_commands.isolate_endpoint(targets)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(
                500, XDR_ERR_INTERNAL, f"Endpoint {', '.join(targets)} not found"),
        )
    return result


@router.post("/endpoints/unisolate")
@xdr_shape("endpoints_unisolate")
def unisolate_endpoint(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Release an endpoint from network isolation."""
    request_data = require_request_data(body)
    targets = endpoint_commands.endpoints_named_by(request_data)
    result = endpoint_commands.unisolate_endpoint(targets)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(
                500, XDR_ERR_INTERNAL, f"Endpoint {', '.join(targets)} not found"),
        )
    return result


@router.post("/endpoints/scan/")
@xdr_shape("endpoints_scan")
def scan_endpoint(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Initiate a scan on an endpoint."""
    request_data = require_request_data(body)
    targets = endpoint_commands.endpoints_named_by(request_data)
    result = endpoint_commands.scan_endpoint(targets)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(
                500, XDR_ERR_INTERNAL, f"Endpoint {', '.join(targets)} not found"),
        )
    return result


@router.post("/endpoints/delete/")
def delete_endpoints(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Delete one or more endpoints."""
    request_data = require_request_data(body)
    endpoint_ids = request_data.get("endpoint_id_list", [])
    return endpoint_commands.delete_endpoints(endpoint_ids)


@router.post("/endpoints/get_policy/")
@xdr_shape("endpoints_get_policy")
def get_policy(
    body: dict = Body(...),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Get the policy applied to an endpoint."""
    request_data = require_request_data(body)
    endpoint_id = request_data.get("endpoint_id", "")
    result = endpoint_queries.get_policy(endpoint_id)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, XDR_ERR_INTERNAL, f"Endpoint {endpoint_id} not found"),
        )
    return result


@router.post("/endpoints/update_agent_name/")
@xdr_shape("endpoints_update_agent_name")
def update_agent_name(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Set the alias of the endpoints the request's ``filters`` select."""
    request_data = require_request_data(body)
    alias = request_data.get("alias", "")
    result = endpoint_commands.update_agent_name(request_data, alias)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, XDR_ERR_INTERNAL, "Endpoint not found"),
        )
    return result


@router.post("/endpoints/terminate_process/")
def terminate_process(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Terminate a process on an endpoint."""
    request_data = require_request_data(body)
    targets = endpoint_commands.endpoints_named_by(request_data)
    result = endpoint_commands.terminate_process(targets, request_data)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(
                500, XDR_ERR_INTERNAL, f"Endpoint {', '.join(targets)} not found"),
        )
    return result


@router.post("/endpoints/quarantine/")
@xdr_shape("endpoints_quarantine")
def quarantine_file(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Quarantine a file on an endpoint."""
    request_data = require_request_data(body)
    targets = endpoint_commands.endpoints_named_by(request_data)
    result = endpoint_commands.quarantine_file(targets, request_data)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(
                500, XDR_ERR_INTERNAL, f"Endpoint {', '.join(targets)} not found"),
        )
    return result


@router.post("/endpoints/restore/")
@xdr_shape("endpoints_restore")
def restore_file(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Restore a quarantined file on an endpoint."""
    request_data = require_request_data(body)
    targets = endpoint_commands.endpoints_named_by(request_data)
    result = endpoint_commands.restore_file(targets, request_data)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(
                500, XDR_ERR_INTERNAL, f"Endpoint {', '.join(targets)} not found"),
        )
    return result


@router.post("/endpoints/file_retrieval/")
@xdr_shape("endpoints_file_retrieval")
def file_retrieval(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Retrieve a file from an endpoint."""
    request_data = require_request_data(body)
    targets = endpoint_commands.endpoints_named_by(request_data)
    result = endpoint_commands.file_retrieval(targets, request_data)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(
                500, XDR_ERR_INTERNAL, f"Endpoint {', '.join(targets)} not found"),
        )
    return result
