"""Sentinel incident query handlers (read-only)."""
from __future__ import annotations

import re

from domain.sentinel.incident import SentinelIncident
from repository.sentinel.alert_repo import sentinel_alert_repo
from repository.sentinel.bookmark_repo import sentinel_bookmark_repo
from repository.sentinel.entity_repo import sentinel_entity_repo
from repository.sentinel.incident_comment_repo import sentinel_incident_comment_repo
from repository.sentinel.incident_repo import sentinel_incident_repo
from utils.sentinel.response import build_arm_list, build_arm_resource


def _incident_to_arm(inc: SentinelIncident) -> dict:
    """Convert a SentinelIncident to ARM resource format."""
    return build_arm_resource("incidents", inc.incident_id, {
        "title": inc.title,
        "description": inc.description,
        "severity": inc.severity,
        "status": inc.status,
        "classification": inc.classification or None,
        "classificationReason": inc.classification_reason or None,
        "classificationComment": inc.classification_comment or None,
        "owner": {
            "objectId": inc.owner_object_id or None,
            "email": inc.owner_email or None,
            "assignedTo": inc.owner_assigned_to or None,
            "userPrincipalName": inc.owner_upn or None,
            "ownerType": inc.owner_type,
        },
        "labels": inc.labels,
        "firstActivityTimeUtc": inc.first_activity_time_utc,
        "lastActivityTimeUtc": inc.last_activity_time_utc,
        "createdTimeUtc": inc.created_time_utc,
        "lastModifiedTimeUtc": inc.last_modified_time_utc,
        "incidentNumber": inc.incident_number,
        "incidentUrl": inc.incident_url or f"https://portal.azure.com/#incident/{inc.incident_id}",
        "providerName": inc.provider_name,
        "providerIncidentId": inc.provider_incident_id,
        "additionalData": {
            "alertsCount": len(inc.alert_ids),
            "bookmarksCount": len(inc.bookmark_ids),
            "commentsCount": len(
                sentinel_incident_comment_repo.get_by_incident_id(inc.incident_id),
            ),
            "alertProductNames": inc.alert_product_names,
            "tactics": inc.tactics,
            "techniques": inc.techniques,
        },
        "relatedAnalyticRuleIds": inc.related_analytic_rule_ids,
    }, etag=inc.etag)


def list_incidents(
    filter_expr: str = "",
    orderby: str = "",
    top: int = 50,
    skip_token: str = "",
) -> dict:
    """List incidents with optional OData-style filtering.

    Args:
        filter_expr: OData $filter expression (basic support).
        orderby:     OData $orderby expression.
        top:         Maximum results.
        skip_token:  Pagination token (offset-based).

    Returns:
        ARM list response dict.
    """
    all_incidents = sentinel_incident_repo.list_all()

    # Basic filter support: status eq 'New'
    if filter_expr:
        all_incidents = _apply_filter(all_incidents, filter_expr)

    # Sort
    if orderby:
        field, _, direction = orderby.partition(" ")
        attr = _odata_to_attr(field)
        reverse = direction.lower() == "desc"
        all_incidents.sort(key=lambda i: getattr(i, attr, ""), reverse=reverse)
    else:
        all_incidents.sort(key=lambda i: i.created_time_utc, reverse=True)

    # Pagination
    offset = int(skip_token) if skip_token else 0
    page = all_incidents[offset:offset + top]

    items = [_incident_to_arm(inc) for inc in page]
    next_link = ""
    if offset + top < len(all_incidents):
        next_link = f"?$skipToken={offset + top}"

    return build_arm_list(items, next_link=next_link)


def get_incident(incident_id: str) -> dict | None:
    """Get a single incident in ARM format."""
    inc = sentinel_incident_repo.get(incident_id)
    if not inc:
        return None
    return _incident_to_arm(inc)


def get_incident_alerts(incident_id: str) -> dict:
    """Get alerts associated with an incident."""
    alerts = sentinel_alert_repo.get_by_incident_id(incident_id)
    items = []
    for alert in alerts:
        items.append(build_arm_resource("securityAlerts", alert.alert_id, {
            "alertDisplayName": alert.alert_display_name,
            "description": alert.description,
            "severity": alert.severity,
            "status": alert.status,
            "productName": alert.product_name,
            "vendorName": alert.vendor_name,
            "tactics": alert.tactics,
            "techniques": alert.techniques,
            "timeGenerated": alert.time_generated,
            "alertLink": alert.alert_link,
        }))
    return build_arm_list(items)


def get_incident_entities(incident_id: str) -> dict:
    """Get entities associated with an incident."""
    inc = sentinel_incident_repo.get(incident_id)
    if not inc:
        return build_arm_list([])

    entities = []
    for eid in inc.entity_ids:
        entity = sentinel_entity_repo.get(eid)
        if entity:
            entities.append({
                "id": f"entities/{entity.entity_id}",
                "name": entity.entity_id,
                "type": "Microsoft.SecurityInsights/entities",
                "kind": entity.kind,
                "properties": entity.properties,
            })
    return {"entities": entities, "metaData": {"count": len(entities)}}


def get_incident_comments(incident_id: str) -> dict:
    """Get comments for an incident."""
    comments = sentinel_incident_comment_repo.get_by_incident_id(incident_id)
    items = []
    for c in comments:
        items.append(build_arm_resource("incidentComments", c.comment_id, {
            "message": c.message,
            "author": {"name": c.author_name, "email": c.author_email},
            "createdTimeUtc": c.created_time_utc,
        }, etag=c.etag))
    return build_arm_list(items)


def get_incident_bookmarks(incident_id: str) -> dict:
    """Get bookmarks for an incident."""
    bookmarks = sentinel_bookmark_repo.get_by_incident_id(incident_id)
    items = []
    for bm in bookmarks:
        items.append(build_arm_resource("bookmarks", bm.bookmark_id, {
            "displayName": bm.display_name,
            "notes": bm.notes,
            "query": bm.query,
            "created": bm.created,
        }, etag=bm.etag))
    return build_arm_list(items)


def _apply_filter(incidents: list, filter_expr: str) -> list:
    """Apply basic OData $filter expressions."""
    # Match: field eq 'value'
    match = re.match(r"properties/(\w+)\s+eq\s+'([^']*)'", filter_expr)
    if not match:
        match = re.match(r"(\w+)\s+eq\s+'([^']*)'", filter_expr)
    if match:
        field = _odata_to_attr(match.group(1))
        value = match.group(2)
        return [i for i in incidents if getattr(i, field, "") == value]

    # Match: createdTimeUtc gt 'datetime'
    gt_match = re.match(r"properties/(\w+)\s+gt\s+'([^']*)'", filter_expr)
    if gt_match:
        field = _odata_to_attr(gt_match.group(1))
        value = gt_match.group(2)
        return [i for i in incidents if getattr(i, field, "") > value]

    return incidents


def _odata_to_attr(field: str) -> str:
    """Map OData field names to Python attribute names."""
    mapping = {
        "title": "title",
        "severity": "severity",
        "status": "status",
        "createdTimeUtc": "created_time_utc",
        "lastModifiedTimeUtc": "last_modified_time_utc",
        "incidentNumber": "incident_number",
    }
    return mapping.get(field, field)
