"""Cortex XDR Hash Exceptions API router.

All endpoints use POST with ``{"request_data": {...}}`` body wrapper.
Responses use ``{"reply": {...}}`` envelope via ``build_xdr_*`` helpers.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends

from api.xdr_auth import require_xdr_auth, require_xdr_write
from application.xdr_hash_exceptions import commands as hash_commands
from application.xdr_hash_exceptions import queries as hash_queries

router = APIRouter(tags=["XDR Hash Exceptions"])


@router.post("/hash_exceptions/blocklist/get/")
def get_blocklist(
    body: dict = Body(...),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """List all blocklist hash exceptions."""
    return hash_queries.get_blocklist()


@router.post("/hash_exceptions/allowlist/get/")
def get_allowlist(
    body: dict = Body(...),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """List all allowlist hash exceptions."""
    return hash_queries.get_allowlist()


@router.post("/hash_exceptions/blocklist/")
def add_to_blocklist(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Add hashes to the blocklist."""
    request_data = body.get("request_data", {})
    hashes = request_data.get("hash_list", [])
    return hash_commands.add_to_blocklist(hashes)


@router.post("/hash_exceptions/blocklist/remove/")
def remove_from_blocklist(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Remove hashes from the blocklist."""
    request_data = body.get("request_data", {})
    hashes = request_data.get("hash_list", [])
    return hash_commands.remove_from_blocklist(hashes)


@router.post("/hash_exceptions/allowlist/")
def add_to_allowlist(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Add hashes to the allowlist."""
    request_data = body.get("request_data", {})
    hashes = request_data.get("hash_list", [])
    return hash_commands.add_to_allowlist(hashes)


@router.post("/hash_exceptions/allowlist/remove/")
def remove_from_allowlist(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Remove hashes from the allowlist."""
    request_data = body.get("request_data", {})
    hashes = request_data.get("hash_list", [])
    return hash_commands.remove_from_allowlist(hashes)
