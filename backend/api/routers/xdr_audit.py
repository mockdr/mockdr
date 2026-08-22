"""Cortex XDR Audit API router.

All endpoints use POST with ``{"request_data": {...}}`` body wrapper.
Responses use ``{"reply": {...}}`` envelope via ``build_xdr_*`` helpers.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends

from api.xdr_auth import require_xdr_auth
from application.xdr_audit import queries as audit_queries
from utils.xdr_fixtures import xdr_shape
from utils.xdr_response import require_request_data

router = APIRouter(tags=["XDR Audit"])


@router.post("/audits/management_logs/")
@xdr_shape("audits_management_logs")
def get_management_logs(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """List management audit logs with optional filtering and pagination."""
    request_data = require_request_data(body)
    return audit_queries.get_management_logs(request_data)


@router.post("/audits/agents_reports/")
@xdr_shape("audits_agents_reports")
def get_agent_reports(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Return agent reports."""
    request_data = require_request_data(body)
    return audit_queries.get_agent_reports(request_data)
