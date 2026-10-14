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


#: The members Incidents - Create Or Update marks Required
#: (learn.microsoft.com/rest/api/securityinsights/incidents/create-or-update,
#: 2024-03-01: `properties.severity`, `properties.status`, `properties.title`).
REQUIRED_PROPERTIES = ("title", "severity", "status")


def missing_required(properties: object) -> list[str]:
    """The required incident properties a PUT body leaves out, in spec order."""
    if not isinstance(properties, dict):
        return list(REQUIRED_PROPERTIES)
    return [name for name in REQUIRED_PROPERTIES if not isinstance(properties.get(name), str)]


def create_or_update_incident(
    incident_id: str, properties: dict,
) -> tuple[SentinelIncident, bool]:
    """Create an incident, or replace the one there.

    ARM's PUT is a replacement, not a merge: what the body leaves out of the
    client-settable properties goes back to its default — an absent `owner`
    unassigns, absent `labels` empties the list, an absent classification
    clears it. PATCH is how ARM merges, and the Incidents API has none. The
    mock merged, so a client that sent a full body missing `owner` believed
    it had unassigned the incident while it stayed assigned.

    What the service owns survives the replacement: `incidentNumber`,
    `createdTimeUtc`, the provider, the alerts, entities and bookmarks the
    incident gathered — and the activity window when the body names none,
    since Sentinel derives it from the alerts.

    Args:
        incident_id: The incident resource name.
        properties:  The ARM properties bag, already checked for the
                     required members.

    Returns:
        The created/updated incident, and whether it was created.
    """
    existing = sentinel_incident_repo.get(incident_id)
    now = utc_now()
    owner = properties.get("owner")
    owner = owner if isinstance(owner, dict) else {}
    labels = properties.get("labels")

    if existing:
        existing.title = properties["title"]
        existing.severity = properties["severity"]
        existing.status = properties["status"]
        existing.description = properties.get("description", "") or ""
        existing.classification = properties.get("classification", "") or ""
        existing.classification_reason = properties.get("classificationReason", "") or ""
        existing.classification_comment = properties.get("classificationComment", "") or ""
        existing.owner_assigned_to = owner.get("assignedTo", "") or ""
        existing.owner_email = owner.get("email", "") or ""
        existing.owner_upn = owner.get("userPrincipalName", "") or ""
        existing.owner_object_id = owner.get("objectId", "") or ""
        existing.owner_type = owner.get("ownerType", "Unknown") or "Unknown"
        existing.labels = labels if isinstance(labels, list) else []
        if "firstActivityTimeUtc" in properties:
            existing.first_activity_time_utc = properties["firstActivityTimeUtc"]
        if "lastActivityTimeUtc" in properties:
            existing.last_activity_time_utc = properties["lastActivityTimeUtc"]
        existing.last_modified_time_utc = now
        existing.etag = uuid.uuid4().hex[:8]
        sentinel_incident_repo.save(existing)
        return existing, False

    incident = SentinelIncident(
        incident_id=incident_id,
        title=properties["title"],
        description=properties.get("description", "") or "",
        severity=properties["severity"],
        status=properties["status"],
        classification=properties.get("classification", "") or "",
        classification_reason=properties.get("classificationReason", "") or "",
        classification_comment=properties.get("classificationComment", "") or "",
        owner_assigned_to=owner.get("assignedTo", "") or "",
        owner_email=owner.get("email", "") or "",
        owner_upn=owner.get("userPrincipalName", "") or "",
        owner_object_id=owner.get("objectId", "") or "",
        owner_type=owner.get("ownerType", "Unknown") or "Unknown",
        labels=labels if isinstance(labels, list) else [],
        incident_number=next_incident_number(),
        created_time_utc=now,
        last_modified_time_utc=now,
        first_activity_time_utc=properties.get("firstActivityTimeUtc", now),
        last_activity_time_utc=properties.get("lastActivityTimeUtc", now),
        provider_name=properties.get("providerName", "Azure Sentinel"),
        provider_incident_id=properties.get("providerIncidentId", incident_id),
        etag=uuid.uuid4().hex[:8],
    )
    sentinel_incident_repo.save(incident)
    return incident, True


def delete_incident(incident_id: str) -> bool:
    """Delete a Sentinel incident.

    Args:
        incident_id: The incident resource name.

    Returns:
        True if found and deleted.
    """
    return sentinel_incident_repo.delete(incident_id)
