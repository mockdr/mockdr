"""Cortex XDR System, RBAC, Tags, Exclusions, Device Control, and Quarantine router.

Groups miscellaneous XDR endpoints that don't warrant their own router module.
All POST endpoints use ``{"request_data": {...}}`` body wrapper.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Body, Depends

from api.xdr_auth import require_xdr_auth, require_xdr_write
from application.xdr_rbac import queries as rbac_queries
from application.xdr_system import queries as system_queries
from utils.xdr_response import build_xdr_list_reply, build_xdr_reply

router = APIRouter(tags=["XDR System"])


# ── System ────────────────────────────────────────────────────────────────────


@router.post("/system/get_tenant_info/")
def get_tenant_info(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Return tenant information."""
    return system_queries.get_tenant_info()


@router.get("/healthcheck")
def healthcheck() -> dict:
    """Health check endpoint (no auth required)."""
    return system_queries.healthcheck()


# ── RBAC ──────────────────────────────────────────────────────────────────────


@router.post("/rbac/get_users/")
def get_users(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """List XDR users."""
    return rbac_queries.get_users()


@router.post("/rbac/get_user_group/")
def get_user_groups(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """List XDR user groups."""
    return rbac_queries.get_user_groups()


@router.post("/rbac/get_roles/")
def get_roles(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """List XDR roles."""
    return rbac_queries.get_roles()


# ── Tags ──────────────────────────────────────────────────────────────────────


@router.post("/tags/agents/assign/")
def assign_tag(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Assign a tag to agents (stub)."""
    request_data = body.get("request_data", {})
    return build_xdr_reply({
        "assigned_count": len(request_data.get("endpoint_ids", [])),
        "tag": request_data.get("tag", ""),
    })


@router.post("/tags/agents/remove/")
def remove_tag(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Remove a tag from agents (stub)."""
    request_data = body.get("request_data", {})
    return build_xdr_reply({
        "removed_count": len(request_data.get("endpoint_ids", [])),
        "tag": request_data.get("tag", ""),
    })


# ── Alert Exclusions ─────────────────────────────────────────────────────────


@router.post("/alerts_exclusion/")
def list_exclusions(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """List alert exclusions (canned data)."""
    exclusions = [
        {
            "exclusion_id": "excl-001",
            "name": "Benign PowerShell Scripts",
            "description": "Exclude known-good PowerShell automation",
            "status": "enabled",
            "alert_fields": {"alert_name": ["*automation*"]},
            "creation_time": 1700000000000,
        },
    ]
    return build_xdr_list_reply(exclusions, total_count=len(exclusions))


@router.post("/alerts_exclusion/add/")
def add_exclusion(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Add an alert exclusion (stub)."""
    request_data = body.get("request_data", {})
    return build_xdr_reply({
        "exclusion_id": str(uuid.uuid4()),
        "name": request_data.get("name", ""),
        "status": "enabled",
    })


@router.post("/alerts_exclusion/delete/")
def delete_exclusion(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Delete an alert exclusion (stub)."""
    return build_xdr_reply(True)


# ── Device Control ────────────────────────────────────────────────────────────


@router.post("/device_control/get_violations/")
def get_device_control_violations(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """List device control violations (canned data)."""
    violations = [
        {
            "violation_id": "viol-001",
            "endpoint_id": "mock-endpoint-001",
            "hostname": "ACME-WS-001",
            "type": "disk_drive",
            "vendor": "SanDisk",
            "product": "Cruzer",
            "serial": "ABC123",
            "timestamp": 1700000000000,
            "ip_address": "10.10.1.100",
            "violation_type": "blocked",
        },
    ]
    return build_xdr_list_reply(violations, total_count=len(violations))


# ── Quarantine Status ─────────────────────────────────────────────────────────


@router.post("/quarantine/status/")
def get_quarantine_status(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """List quarantine status entries (canned data)."""
    entries = [
        {
            "file_hash": "a" * 64,
            "file_path": "C:\\Users\\analyst\\Downloads\\sample.exe",
            "endpoint_id": "mock-endpoint-001",
            "hostname": "ACME-WS-001",
            "status": "quarantined",
            "date_detected": 1700000000000,
        },
    ]
    return build_xdr_list_reply(entries, total_count=len(entries))
