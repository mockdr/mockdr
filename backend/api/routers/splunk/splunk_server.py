"""Splunk server info and status router."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from api.splunk_auth import require_splunk_auth
from utils.splunk.response import build_splunk_entry, build_splunk_envelope

router = APIRouter(tags=["Splunk Server"])

#: Every key a real Splunk 10.4.2 reports, with values a client can parse
#: as it would the real ones. Sixteen of these were here before; the
#: other thirty-five were missing, and a client reading e.g. `kvStoreStatus`
#: or `health_info` to decide whether the instance is usable found nothing.
_SERVER_INFO = {
    "activeLicenseGroup": "Enterprise",
    "activeLicenseSubgroup": "Production",
    "addOns": {"hadoop": {"parameters": {
        "erp_type": "report", "guid": "6F416E61-B40E-461C-A782-CBC186E98133", "maxNodes": "200",
    }, "type": "external_results_provider"}},
    "build": "a1b2c3d4e5f6",
    "cgroups_version": "V2",
    "conf_generation": 12,
    "cpu_arch": "x86_64",
    "eai:acl": None,
    "federated_search_enabled": True,
    "fips_mode": False,
    "guid": "MOCKDR-SPLUNK-0000-0000-000000000001",
    "health_info": "green",
    "health_version": 4289799160,
    "host": "mockdr-splunk",
    "host_fqdn": "mockdr-splunk",
    "host_resolved": "mockdr-splunk",
    "isConverged": False,
    "isForwarding": False,
    "isFree": False,
    "isTrial": False,
    "kvStoreStatus": "ready",
    "licenseKeys": ["0000000000000000000000000000000000000000000000000000000000000000"],
    "licenseSignature": "00000000000000000000000000000000",
    "licenseState": "OK",
    "license_labels": ["Splunk Enterprise"],
    "manager_guid": "MOCKDR-SPLUNK-0000-0000-000000000001",
    "manager_uri": "self",
    "master_guid": "MOCKDR-SPLUNK-0000-0000-000000000001",
    "master_uri": "self",
    "max_users": 4294967295,
    "mode": "normal",
    "numberOfCores": 8,
    "numberOfVirtualCores": 8,
    "os_build": "#1 SMP",
    "os_name": "Linux",
    "os_name_extended": "Linux",
    "os_version": "5.15.0",
    "physicalMemoryMB": 32768,
    "product_type": "enterprise",
    "rtsearch_enabled": True,
    "serverName": "mockdr-splunk",
    "server_roles": ["indexer", "search_head", "kv_store", "license_master", "license_manager"],
    "shutting_down": "0",
    "startup_time": 1755000000,
    "staticAssetId": "0000000000000000000000000000000000000000000000000000000000000000",
    "version": "9.4.0",
    "versionControlEnabled": True,
}


@router.get("/services/server/info")
def server_info(
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Return Splunk server info.

    This was unauthenticated "for health checks". splunkd does not agree:
    it answers an anonymous caller 401 (measured on 10.4.2), and its
    unauthenticated health endpoint is HEC's ``/services/collector/health``,
    not this. The entry also carries only ``alternate`` and ``list`` links,
    no ``fields`` block, and the collection offers no ``create``.
    """
    entry = build_splunk_entry(
        "server-info", _SERVER_INFO, collection="server/info",
        links=("alternate", "list"), fields=False,
    )
    return build_splunk_envelope([entry], total=1, links={})


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
    entry = build_splunk_entry("server-status", status, acl_extra={"perms": None})
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
