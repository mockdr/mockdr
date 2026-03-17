"""Cortex XDR IOC Indicators API router.

All endpoints use POST with ``{"request_data": {...}}`` body wrapper.
Responses use ``{"reply": {...}}`` envelope via ``build_xdr_*`` helpers.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends

from api.xdr_auth import require_xdr_write
from application.xdr_iocs import commands as ioc_commands

router = APIRouter(tags=["XDR IOCs"])


@router.post("/indicators/tim_insert_jsons/")
def insert_iocs(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Push IOC indicators in JSON format."""
    request_data = body.get("request_data", {})
    iocs = request_data.get("indicators", [])
    return ioc_commands.insert_iocs(iocs)


@router.post("/indicators/enable_iocs")
def enable_iocs(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Enable one or more IOC indicators."""
    request_data = body.get("request_data", {})
    ioc_ids = request_data.get("ioc_id_list", [])
    return ioc_commands.enable_iocs(ioc_ids)


@router.post("/indicators/disable_iocs")
def disable_iocs(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Disable one or more IOC indicators."""
    request_data = body.get("request_data", {})
    ioc_ids = request_data.get("ioc_id_list", [])
    return ioc_commands.disable_iocs(ioc_ids)
