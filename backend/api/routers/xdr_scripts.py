"""Cortex XDR Scripts API router.

All endpoints use POST with ``{"request_data": {...}}`` body wrapper.
Responses use ``{"reply": {...}}`` envelope via ``build_xdr_*`` helpers.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException

from api.xdr_auth import require_xdr_auth, require_xdr_write
from application.xdr_scripts import commands as script_commands
from application.xdr_scripts import queries as script_queries
from utils.xdr_response import build_xdr_error

router = APIRouter(tags=["XDR Scripts"])


@router.post("/scripts/get_scripts/")
def get_scripts(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """List scripts with optional filtering and pagination."""
    request_data = body.get("request_data", {})
    return script_queries.get_scripts(request_data)


@router.post("/scripts/get_script_metadata/")
def get_script_metadata(
    body: dict = Body(...),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Get metadata for a single script."""
    request_data = body.get("request_data", {})
    script_id = request_data.get("script_id", "")
    result = script_queries.get_script_metadata(script_id)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, f"Script {script_id} not found"),
        )
    return result


@router.post("/scripts/run_script/")
def run_script(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Execute a script on one or more endpoints."""
    request_data = body.get("request_data", {})
    endpoint_ids = request_data.get("endpoint_id_list", [])
    script_id = request_data.get("script_id", "")
    result = script_commands.run_script(endpoint_ids, script_id, request_data)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, f"Script {script_id} not found"),
        )
    return result


@router.post("/scripts/get_script_execution_status/")
def get_execution_status(
    body: dict = Body(...),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Get the execution status of a script run action."""
    request_data = body.get("request_data", {})
    action_id = request_data.get("action_id", "")
    result = script_queries.get_execution_status(action_id)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, f"Action {action_id} not found"),
        )
    return result


@router.post("/scripts/get_script_execution_results")
def get_execution_results(
    body: dict = Body(...),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Get the execution results of a script run action."""
    request_data = body.get("request_data", {})
    action_id = request_data.get("action_id", "")
    result = script_queries.get_execution_results(action_id)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, f"Action {action_id} not found"),
        )
    return result
