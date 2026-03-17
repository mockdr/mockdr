"""Sentinel Data Connectors router."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from api.sentinel_auth import require_sentinel_auth
from domain.sentinel.data_connector import SentinelDataConnector
from repository.sentinel.data_connector_repo import sentinel_data_connector_repo
from utils.sentinel.response import build_arm_error, build_arm_list, build_arm_resource

router = APIRouter(tags=["Sentinel Data Connectors"])

_WS = (
    "/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
    "/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
    "/providers/Microsoft.SecurityInsights"
)


def _connector_to_arm(dc: SentinelDataConnector) -> dict:
    return build_arm_resource("dataConnectors", dc.connector_id, {
        "connectorUiConfig": {"title": dc.name},
        "dataTypes": {"state": dc.data_types_state},
        "kind": dc.kind,
    }, etag=dc.etag)


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
            detail=build_arm_error("NotFound", f"Data connector '{connector_id}' not found"),
        )
    return _connector_to_arm(dc)
