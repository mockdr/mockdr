"""Cortex XDR Hash Exceptions API router.

All endpoints use POST with ``{"request_data": {...}}`` body wrapper.
Responses use ``{"reply": {...}}`` envelope via ``build_xdr_*`` helpers.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends

from api.xdr_auth import require_xdr_write
from application.xdr_hash_exceptions import commands as hash_commands
from utils.xdr_fixtures import xdr_shape
from utils.xdr_response import require_request_data, require_str_list

router = APIRouter(tags=["XDR Hash Exceptions"])


@router.post("/hash_exceptions/blocklist/")
@xdr_shape("hash_exceptions_blocklist")
def add_to_blocklist(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Add hashes to the blocklist."""
    request_data = require_request_data(body)
    return hash_commands.add_to_blocklist(
        require_str_list(request_data, "hash_list"),
        str(request_data.get("comment") or ""),
        request_data.get("incident_id"),
    )


@router.post("/hash_exceptions/blocklist/remove/")
def remove_from_blocklist(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Remove hashes from the blocklist."""
    request_data = require_request_data(body)
    return hash_commands.remove_from_blocklist(require_str_list(request_data, "hash_list"))


@router.post("/hash_exceptions/allowlist/")
@xdr_shape("hash_exceptions_allowlist")
def add_to_allowlist(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Add hashes to the allowlist."""
    request_data = require_request_data(body)
    return hash_commands.add_to_allowlist(
        require_str_list(request_data, "hash_list"),
        str(request_data.get("comment") or ""),
        request_data.get("incident_id"),
    )


@router.post("/hash_exceptions/allowlist/remove/")
def remove_from_allowlist(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Remove hashes from the allowlist."""
    request_data = require_request_data(body)
    return hash_commands.remove_from_allowlist(require_str_list(request_data, "hash_list"))
