"""Cortex XDR IOC Indicators API router.

All endpoints use POST with ``{"request_data": {...}}`` body wrapper.
Responses use ``{"reply": {...}}`` envelope via ``build_xdr_*`` helpers.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends

from api.xdr_auth import require_xdr_write
from application.xdr_iocs import commands as ioc_commands
from utils.xdr_response import require_request_data

router = APIRouter(tags=["XDR IOCs"])


@router.post("/indicators/tim_insert_jsons/")
def insert_iocs(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Push IOC indicators in JSON format."""
    request_data = require_request_data(body)
    iocs = request_data.get("indicators", [])
    return ioc_commands.insert_iocs(iocs)


