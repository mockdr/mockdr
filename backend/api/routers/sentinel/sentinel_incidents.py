"""Sentinel Incidents router."""
from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api.sentinel_auth import require_sentinel_auth
from application.sentinel.commands import comments as comment_cmds
from application.sentinel.commands import incidents as incident_cmds
from application.sentinel.queries import incidents as incident_queries
from utils.sentinel.response import build_arm_error, build_arm_resource

router = APIRouter(tags=["Sentinel Incidents"])

_WS = (
    "/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
    "/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
    "/providers/Microsoft.SecurityInsights"
)


# ── Incidents CRUD ────────────────────────────────────────────────────────


@router.get(_WS + "/incidents")
def list_incidents(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    filter: str = Query(default=None, alias="$filter"),
    orderby: str = Query(default=None, alias="$orderby"),
    top: int = Query(default=None, alias="$top"),
    skip_token: str = Query(default=None, alias="$skipToken"),
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """List incidents."""
    return incident_queries.list_incidents(
        filter_expr=filter or "",
        orderby=orderby or "",
        top=min(top or 50, 1000),
        skip_token=skip_token or "",
    )


@router.get(_WS + "/incidents/{incident_id}")
def get_incident(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    incident_id: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Get a single incident."""
    result = incident_queries.get_incident(incident_id)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=build_arm_error("NotFound", f"Incident '{incident_id}' not found"),
        )
    return result


@router.put(_WS + "/incidents/{incident_id}")
async def create_or_update_incident(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    incident_id: str,
    request: Request,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Create or update an incident."""
    body = await request.json()
    properties = body.get("properties", {})
    incident_cmds.create_or_update_incident(incident_id, properties)
    return incident_queries.get_incident(incident_id) or {}


@router.delete(_WS + "/incidents/{incident_id}")
def delete_incident(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    incident_id: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Delete an incident."""
    if not incident_cmds.delete_incident(incident_id):
        raise HTTPException(
            status_code=404,
            detail=build_arm_error("NotFound", f"Incident '{incident_id}' not found"),
        )
    return {}


# ── Incident sub-resources ────────────────────────────────────────────────


@router.post(_WS + "/incidents/{incident_id}/alerts")
def list_incident_alerts(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    incident_id: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """List alerts for an incident."""
    return incident_queries.get_incident_alerts(incident_id)


@router.post(_WS + "/incidents/{incident_id}/entities")
def list_incident_entities(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    incident_id: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """List entities for an incident."""
    return incident_queries.get_incident_entities(incident_id)


@router.post(_WS + "/incidents/{incident_id}/bookmarks")
def list_incident_bookmarks(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    incident_id: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """List bookmarks for an incident."""
    return incident_queries.get_incident_bookmarks(incident_id)


# ── Comments ──────────────────────────────────────────────────────────────


@router.get(_WS + "/incidents/{incident_id}/comments")
def list_incident_comments(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    incident_id: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """List comments for an incident."""
    return incident_queries.get_incident_comments(incident_id)


@router.get(_WS + "/incidents/{incident_id}/comments/{comment_id}")
def get_incident_comment(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    incident_id: str,
    comment_id: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Get a single comment."""
    result = incident_queries.get_incident_comments(incident_id)
    comments = result.get("value", [])
    for c in comments:
        if c.get("name") == comment_id or c.get("id", "").endswith(f"/{comment_id}"):
            return cast(dict[str, Any], c)
    raise HTTPException(
        status_code=404,
        detail=build_arm_error("NotFound", f"Comment '{comment_id}' not found"),
    )


@router.put(_WS + "/incidents/{incident_id}/comments/{comment_id}")
async def create_or_update_comment(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    incident_id: str,
    comment_id: str,
    request: Request,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Create or update a comment on an incident."""
    body = await request.json()
    message = body.get("properties", {}).get("message", "")
    comment = comment_cmds.create_or_update_comment(incident_id, comment_id, message)
    return build_arm_resource("incidentComments", comment.comment_id, {
        "message": comment.message,
        "author": {"name": comment.author_name, "email": comment.author_email},
        "createdTimeUtc": comment.created_time_utc,
    }, etag=comment.etag)


@router.delete(_WS + "/incidents/{incident_id}/comments/{comment_id}")
def delete_incident_comment(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    incident_id: str,
    comment_id: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Delete a comment."""
    comment_cmds.delete_comment(comment_id)
    return {}


# ── Relations ─────────────────────────────────────────────────────────────


@router.get(_WS + "/incidents/{incident_id}/relations")
def list_incident_relations(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    incident_id: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """List relations for an incident (stub)."""
    return {"value": []}


@router.put(_WS + "/incidents/{incident_id}/relations/{relation_name}")
async def create_or_update_relation(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    incident_id: str,
    relation_name: str,
    request: Request,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Create or update a relation (stub)."""
    body = await request.json()
    return cast(dict[str, Any], body)


@router.delete(_WS + "/incidents/{incident_id}/relations/{relation_name}")
def delete_incident_relation(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    incident_id: str,
    relation_name: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Delete a relation (stub)."""
    return {}


# ── Run Playbook ──────────────────────────────────────────────────────────


@router.post(_WS + "/incidents/{incident_id}/runPlaybook")
def run_playbook(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    incident_id: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Run a playbook on an incident (stub)."""
    return {"status": "Success"}
