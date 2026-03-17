"""Sentinel incident command handlers (mutations)."""
from __future__ import annotations

import uuid

from domain.sentinel.incident import SentinelIncident
from repository.sentinel.incident_repo import sentinel_incident_repo
from utils.dt import utc_now


def next_incident_number() -> int:
    """Return the next auto-incrementing incident number."""
    all_incidents = sentinel_incident_repo.list_all()
    if not all_incidents:
        return 1
    return max(i.incident_number for i in all_incidents) + 1


def create_or_update_incident(incident_id: str, properties: dict) -> SentinelIncident:
    """Create or update a Sentinel incident.

    Args:
        incident_id: The incident resource name.
        properties:  The ARM properties bag.

    Returns:
        The created/updated incident.
    """
    existing = sentinel_incident_repo.get(incident_id)
    now = utc_now()

    if existing:
        # Update
        if "title" in properties:
            existing.title = properties["title"]
        if "description" in properties:
            existing.description = properties["description"]
        if "severity" in properties:
            existing.severity = properties["severity"]
        if "status" in properties:
            existing.status = properties["status"]
        if "classification" in properties:
            existing.classification = properties["classification"]
        if "classificationReason" in properties:
            existing.classification_reason = properties["classificationReason"]
        if "classificationComment" in properties:
            existing.classification_comment = properties["classificationComment"]
        if "owner" in properties:
            owner = properties["owner"]
            existing.owner_assigned_to = owner.get("assignedTo", existing.owner_assigned_to)
            existing.owner_email = owner.get("email", existing.owner_email)
            existing.owner_upn = owner.get("userPrincipalName", existing.owner_upn)
            existing.owner_object_id = owner.get("objectId", existing.owner_object_id)
        if "labels" in properties:
            existing.labels = properties["labels"]
        existing.last_modified_time_utc = now
        existing.etag = uuid.uuid4().hex[:8]
        sentinel_incident_repo.save(existing)
        return existing

    # Create new
    incident = SentinelIncident(
        incident_id=incident_id,
        title=properties.get("title", ""),
        description=properties.get("description", ""),
        severity=properties.get("severity", "Medium"),
        status=properties.get("status", "New"),
        incident_number=next_incident_number(),
        created_time_utc=now,
        last_modified_time_utc=now,
        first_activity_time_utc=properties.get("firstActivityTimeUtc", now),
        last_activity_time_utc=properties.get("lastActivityTimeUtc", now),
        provider_name=properties.get("providerName", "Azure Sentinel"),
        provider_incident_id=properties.get("providerIncidentId", incident_id),
        etag=uuid.uuid4().hex[:8],
    )
    if "owner" in properties:
        owner = properties["owner"]
        incident.owner_assigned_to = owner.get("assignedTo", "")
        incident.owner_email = owner.get("email", "")
        incident.owner_upn = owner.get("userPrincipalName", "")
    if "labels" in properties:
        incident.labels = properties["labels"]

    sentinel_incident_repo.save(incident)
    return incident


def delete_incident(incident_id: str) -> bool:
    """Delete a Sentinel incident.

    Args:
        incident_id: The incident resource name.

    Returns:
        True if found and deleted.
    """
    return sentinel_incident_repo.delete(incident_id)
