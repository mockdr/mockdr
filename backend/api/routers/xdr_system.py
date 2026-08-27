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
    """List the user groups the body names, or all of them."""
    names = (body.get("request_data") or {}).get("group_names")
    return rbac_queries.get_user_groups(names if isinstance(names, list) else None)


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
    """List the device-control violations this tenant's endpoints raised.

    Three things were wrong at once, and all three were invisible from a
    single answer. Cortex answers the rows under `reply.violations` — the
    OpenAPI document and the recorded sample agree — and mockdr answered them
    under `reply.data`, so a client reading the documented member found an
    empty list beside a populated one it had never heard of. The row named
    the address `ip_address` where Cortex names it `ip`. And the one row was
    canned: `mock-endpoint-001` on `ACME-WS-001`, an endpoint
    `get_endpoint` has never listed.
    """
    from repository.xdr_endpoint_repo import xdr_endpoint_repo  # noqa: PLC0415

    devices = [
        ("disk_drive", "SanDisk", "5678", "Cruzer", "0x1234"),
        ("disk_drive", "Kingston", "0951", "DataTraveler", "0x1666"),
        ("cd_rom", "Samsung", "04e8", "SE-208", "0x6103"),
    ]
    violations = []
    for index, endpoint in enumerate(xdr_endpoint_repo.list_all()[:12]):
        kind, vendor, vendor_id, product, product_id = devices[index % len(devices)]
        violations.append({
            "violation_id": index + 1,
            "endpoint_id": endpoint.endpoint_id,
            "hostname": endpoint.endpoint_name,
            "ip": endpoint.ip[0] if getattr(endpoint, "ip", None) else "",
            "os_type": endpoint.os_type,
            "type": kind,
            "vendor": vendor,
            "vendor_id": vendor_id,
            "product": product,
            "product_id": product_id,
            "serial": f"SN{endpoint.endpoint_id[-8:].upper()}",
            "username": endpoint.users[0] if endpoint.users else "",
            "timestamp": endpoint.last_seen,
        })
    return build_xdr_list_reply(
        violations, total_count=len(violations), key="violations",
    )


# ── Quarantine Status ─────────────────────────────────────────────────────────


@router.post("/quarantine/status/")
@xdr_shape("quarantine_status")
def get_quarantine_status(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Report the status of the files the body asks about.

    `request_data.files` is what this route is *for* — a client asks whether
    the file it just quarantined is quarantined — and mockdr answered the
    same canned row whatever was asked, so a playbook read someone else's
    file back and believed it was its own.
    """
    # The product answers a bare list of {endpoint_id, file_hash, file_path,
    # status} (recorded in the XSOAR pack), not a paged envelope.
    asked = (body.get("request_data") or {}).get("files")
    if not isinstance(asked, list) or not asked:
        return build_xdr_reply([])
    entries = [
        {
            "endpoint_id": str(item.get("endpoint_id", "")),
            "file_hash": str(item.get("file_hash", "")),
            "file_path": str(item.get("file_path", "")),
            # Every file this mock is asked about is quarantined: it holds no
            # quarantine store of its own, and answering "no" for a file a
            # client has just quarantined would be the worse invention.
            "status": "quarantined",
        }
        for item in asked
        if isinstance(item, dict)
    ]
    return build_xdr_reply(entries)
