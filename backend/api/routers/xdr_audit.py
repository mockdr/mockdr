"""Cortex XDR Audit API router.

All endpoints use POST with ``{"request_data": {...}}`` body wrapper.
Responses use ``{"reply": {...}}`` envelope via ``build_xdr_*`` helpers.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends

from api.xdr_auth import require_xdr_auth
from application.xdr_audit import queries as audit_queries

router = APIRouter(tags=["XDR Audit"])


@router.post("/audits/management_logs/")
def get_management_logs(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """List management audit logs with optional filtering and pagination."""
    request_data = body.get("request_data", {})
    return audit_queries.get_management_logs(request_data)


@router.post("/audits/agents_reports/")
def get_agent_reports(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Return agent reports."""
    request_data = body.get("request_data", {})
    return audit_queries.get_agent_reports(request_data)
