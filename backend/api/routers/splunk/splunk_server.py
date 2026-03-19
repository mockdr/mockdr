"""Splunk server info and status router."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from api.splunk_auth import require_splunk_auth
from utils.splunk.response import build_splunk_entry, build_splunk_envelope

router = APIRouter(tags=["Splunk Server"])

_SERVER_INFO = {
    "build": "a1b2c3d4e5f6",
    "cpu_arch": "x86_64",
    "guid": "MOCKDR-SPLUNK-0000-0000-000000000001",
    "isFree": False,
    "isTrial": False,
    "licenseState": "OK",
    "master_guid": "MOCKDR-SPLUNK-0000-0000-000000000001",
    "mode": "normal",
    "os_build": "#1 SMP",
    "os_name": "Linux",
    "os_version": "5.15.0",
    "product_type": "enterprise",
    "rtsearch_enabled": True,
    "serverName": "mockdr-splunk",
    "server_roles": [
        "indexer",
        "search_head",
        "kv_store",
        "license_master",
    ],
    "version": "9.4.0",
}


@router.get("/services/server/info")
def server_info(
    output_mode: str = "json",
) -> dict:
    """Return Splunk server info (no auth required for health checks)."""
    entry = build_splunk_entry("server-info", _SERVER_INFO)
    return build_splunk_envelope([entry], total=1)


@router.get("/services/server/status")
def server_status(
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Return Splunk server status."""
    status = {
        "health": "green",
        "splunkd": "running",
        "kvstore": "ready",
    }
    entry = build_splunk_entry("server-status", status)
    return build_splunk_envelope([entry], total=1)


@router.get("/services/server/settings")
def server_settings(
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Return Splunk server settings."""
    settings = {
        "SPLUNK_HOME": "/opt/splunk",
        "SPLUNK_DB": "/opt/splunk/var/lib/splunk",
        "host": "mockdr-splunk",
        "httpport": "8089",
        "mgmtHostPort": "0.0.0.0:8089",
        "enableSplunkWebSSL": False,
    }
    entry = build_splunk_entry("server-settings", settings)
    return build_splunk_envelope([entry], total=1)
