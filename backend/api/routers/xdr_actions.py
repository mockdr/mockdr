"""Cortex XDR Actions API router.

All endpoints use POST with ``{"request_data": {...}}`` body wrapper.
Responses use ``{"reply": {...}}`` envelope via ``build_xdr_*`` helpers.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException

from api.xdr_auth import require_xdr_auth
from application.xdr_actions import queries as action_queries
from utils.xdr_response import build_xdr_error

router = APIRouter(tags=["XDR Actions"])


@router.post("/actions/get_action_status/")
def get_action_status(
    body: dict = Body(...),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Get the status of a response action."""
    request_data = body.get("request_data", {})
    action_id = request_data.get("action_id", "")
    result = action_queries.get_action_status(action_id)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, f"Action {action_id} not found"),
        )
    return result


@router.post("/actions/file_retrieval_details/")
def get_file_retrieval_details(
    body: dict = Body(...),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Get file retrieval download details for an action."""
    request_data = body.get("request_data", {})
    action_id = request_data.get("action_id", "")
    result = action_queries.get_file_retrieval_details(action_id)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, f"Action {action_id} not found"),
        )
    return result
