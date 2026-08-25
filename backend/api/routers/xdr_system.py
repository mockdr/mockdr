"""Cortex XDR System, RBAC, Tags, Exclusions, Device Control, and Quarantine router.

Groups miscellaneous XDR endpoints that don't warrant their own router module.
All POST endpoints use ``{"request_data": {...}}`` body wrapper.
"""

from __future__ import annotations

import random
import time

from fastapi import APIRouter, Body, Depends

from api.xdr_auth import require_xdr_auth, require_xdr_write
from application.xdr_endpoints import commands as endpoint_commands
from application.xdr_rbac import queries as rbac_queries
from application.xdr_system import queries as system_queries
from utils.xdr_fixtures import xdr_shape
from utils.xdr_response import build_xdr_list_reply, build_xdr_reply, require_request_data

router = APIRouter(tags=["XDR System"])


def _recent_ms() -> int:
    """An epoch-millisecond timestamp within the last day, so a time-bounded client sees it."""
    return int((time.time() - random.uniform(0, 86400)) * 1000)  # noqa: S311


# ── System ────────────────────────────────────────────────────────────────────


@router.post("/system/get_tenant_info/")
@xdr_shape("system_get_tenant_info")
def get_tenant_info(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Return tenant information."""
    return system_queries.get_tenant_info()


@router.get("/healthcheck")
@xdr_shape("healthcheck")
def healthcheck() -> dict:
    """Health check endpoint (no auth required)."""
    return system_queries.healthcheck()


# ── RBAC ──────────────────────────────────────────────────────────────────────


@router.post("/rbac/get_users/")
@xdr_shape("rbac_get_users")
def get_users(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """List XDR users."""
    return rbac_queries.get_users()


@router.post("/rbac/get_user_group/")
@xdr_shape("rbac_get_user_group")
def get_user_groups(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """List XDR user groups."""
    return rbac_queries.get_user_groups()


@router.post("/rbac/get_roles/")
@xdr_shape("rbac_get_roles")
def get_roles(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """List XDR roles."""
    return rbac_queries.get_roles()


# ── Tags ──────────────────────────────────────────────────────────────────────


@router.post("/tags/agents/assign/")
@xdr_shape("tags_agents_assign")
def assign_tag(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Assign a tag to the agents the request names.

    The body carries the endpoints twice over: ``context.lcaas_id`` lists
    them, and ``request_data.filters`` narrows them. The route used to read
    ``endpoint_ids`` — a key the documented body has never had — count it,
    and answer with the count. Nothing was tagged, and the answer carried
    two members Cortex's own reply does not.
    """
    return endpoint_commands.tag_endpoints(body, assign=True)


@router.post("/tags/agents/remove/")
@xdr_shape("tags_agents_remove")
def remove_tag(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Remove a tag from the agents the request names."""
    return endpoint_commands.tag_endpoints(body, assign=False)


# ── Alert Exclusions ─────────────────────────────────────────────────────────


@router.post("/alerts_exclusion/")
@xdr_shape("alerts_exclusion")
def list_exclusions(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """List alert exclusions (canned data)."""
    # Recorded (XSOAR CoreIRApiModule get_exclusion_response.json): a bare list
    # of ALERT_WHITELIST_* rows in reply, not a paged envelope with invented
    # exclusion_id/name/status fields.
    exclusions = [
        {
            "ALERT_WHITELIST_ID": 1,
            "ALERT_WHITELIST_NAME": "Benign PowerShell Scripts",
            "ALERT_WHITELIST_COMMENT": "Exclude known-good PowerShell automation",
            "ALERT_WHITELIST_MODIFY_TIME": _recent_ms(),
            "ALERT_WHITELIST_HITS": 0,
        },
    ]
    return build_xdr_reply(exclusions)


@router.post("/alerts_exclusion/add/")
@xdr_shape("alerts_exclusion_add")
def add_exclusion(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Add an alert exclusion (stub)."""
    require_request_data(body)
    # Recorded: {"reply": {"rule_id": 42}}
    return build_xdr_reply({"rule_id": int(time.time()) % 100000})


@router.post("/alerts_exclusion/delete/")
@xdr_shape("alerts_exclusion_delete")
def delete_exclusion(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Delete an alert exclusion (stub)."""
    request_data = require_request_data(body)
    ids = request_data.get("alert_exclusion_id")
    # Recorded: {"reply": {"rule_id": [42]}}
    return build_xdr_reply({"rule_id": ids if isinstance(ids, list) else [ids]})


# ── Device Control ────────────────────────────────────────────────────────────


@router.post("/device_control/get_violations/")
@xdr_shape("device_control_get_violations")
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
            "timestamp": _recent_ms(),
            "ip_address": "10.10.1.100",
            "violation_type": "blocked",
        },
    ]
    return build_xdr_list_reply(violations, total_count=len(violations))


# ── Quarantine Status ─────────────────────────────────────────────────────────


@router.post("/quarantine/status/")
@xdr_shape("quarantine_status")
def get_quarantine_status(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """List quarantine status entries (canned data)."""
    # The product answers a bare list of {endpoint_id, file_hash, file_path,
    # status} (recorded in the XSOAR pack), not a paged envelope.
    entries = [
        {
            "endpoint_id": "mock-endpoint-001",
            "file_hash": "a" * 64,
            "file_path": "C:\\Users\\analyst\\Downloads\\sample.exe",
            "status": "quarantined",
        },
    ]
    return build_xdr_reply(entries)
