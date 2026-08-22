"""Sentinel Data Connectors router."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from api.sentinel_auth import require_sentinel_auth
from domain.sentinel.data_connector import SentinelDataConnector
from repository.sentinel.data_connector_repo import sentinel_data_connector_repo
from utils.sentinel.response import (
    build_arm_error,
    build_arm_list,
    build_arm_resource,
    fixture_properties,
)

router = APIRouter(tags=["Sentinel Data Connectors"])

_WS = (
    "/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
    "/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
    "/providers/Microsoft.SecurityInsights"
)


_TENANT = "00000000-0000-0000-0000-000000000000"


def _with_states(node: dict, state: str) -> dict:
    """Every ``state`` leaf in a connector's ``dataTypes`` set to ``state``."""
    return {
        k: (state if k == "state" else _with_states(v, state) if isinstance(v, dict) else v)
        for k, v in node.items()
    }


def _connector_to_arm(dc: SentinelDataConnector) -> dict:
    """A data connector in the shape its kind declares in the 2024-03-01 spec.

    The eight stable kinds carry ``tenantId`` and a kind-specific ``dataTypes``
    tree (``{"alerts": {"state": ...}}`` for Defender, ``{"exchange", "sharePoint",
    "teams"}`` for Office 365, …). ``GenericUI`` is preview-only and keeps its
    ``connectorUiConfig``. This used to emit one invented shape for every kind.
    """
    declared = fixture_properties("dataConnectors", dc.kind)
    if "connectorUiConfig" in declared:
        # Codeless: the UI definition is the connector. Shape from the
        # 2025-10-01-preview CodelessUiConnectorConfigProperties.
        props = declared
        props["connectorUiConfig"].update({
            "title": dc.name,
            "publisher": dc.name.split(" ")[0],
            "descriptionMarkdown": f"Ingest {dc.name} events into Microsoft Sentinel.",
            "graphQueriesTableName": f"{dc.name.replace(' ', '')}_CL",
            "availability": {"status": 1, "isPreview": False},
            "dataTypes": [{
                "name": f"{dc.name.replace(' ', '')}_CL",
                "lastDataReceivedQuery": (
                    f"{dc.name.replace(' ', '')}_CL | summarize max(TimeGenerated)"
                ),
            }],
        })
    elif declared:
        props = _with_states(declared, dc.data_types_state)
        props["tenantId"] = _TENANT
    else:
        props = {"dataTypes": {"state": dc.data_types_state}}
    return build_arm_resource("dataConnectors", dc.connector_id, props, etag=dc.etag, kind=dc.kind)


@router.get(_WS + "/dataConnectors")
def list_all_data_connectors(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """List all data connectors."""
    connectors = sentinel_data_connector_repo.list_all()
    return build_arm_list([_connector_to_arm(dc) for dc in connectors])


@router.get(_WS + "/dataConnectors/{connector_id}")
def get_single_data_connector(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    connector_id: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Get a single data connector."""
    dc = sentinel_data_connector_repo.get(connector_id)
    if not dc:
        raise HTTPException(
            status_code=404,
            detail=build_arm_error(
                "ResourceNotFound",
                f"Data connector '{connector_id}' not found",
            ),
        )
    return _connector_to_arm(dc)
