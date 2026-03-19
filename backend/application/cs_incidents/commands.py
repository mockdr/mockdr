"""CrowdStrike Falcon Incident command handlers (mutations)."""
from __future__ import annotations

from repository.cs_incident_repo import cs_incident_repo
from utils.cs_response import build_cs_action_response
from utils.dt import utc_now

# Map of status codes to state strings for the real CS API.
_STATUS_TO_STATE: dict[int, str] = {
    20: "open",
    25: "reopened",
    30: "in_progress",
    40: "closed",
}


def perform_incident_action(
    ids: list[str],
    action_parameters: list[dict],
) -> dict:
    """Update incident fields via action parameters.

    Supported parameter names:
    - ``update_status``: value is a status code (20, 25, 30, 40).
    - ``update_assigned_to_v2``: value is a user UUID.
    - ``add_tag``: value is a tag string.
    - ``delete_tag``: value is a tag string.
    - ``update_name``: value is the new incident name.
    - ``update_description``: value is the new description.

    Args:
        ids:               List of incident IDs to update.
        action_parameters: List of ``{"name": str, "value": str}`` dicts
                           describing the mutations to apply.

    Returns:
        CS action response with affected incident resources.
    """
    affected: list[dict] = []
    for incident_id in ids:
        incident = cs_incident_repo.get(incident_id)
        if not incident:
            continue
        for param in action_parameters:
            name = param.get("name", "")
            value = param.get("value", "")
            if name == "update_status":
                status_code = int(value)
                incident.status = status_code
                incident.state = _STATUS_TO_STATE.get(status_code, incident.state)
            elif name == "update_assigned_to_v2":
                incident.assigned_to = value
            elif name == "add_tag":
                if value not in incident.tags:
                    incident.tags.append(value)
            elif name == "delete_tag":
                incident.tags = [t for t in incident.tags if t != value]
            elif name == "update_name":
                incident.name = value
            elif name == "update_description":
                incident.description = value
        incident.modified_timestamp = utc_now()
        cs_incident_repo.save(incident)
        affected.append({"id": incident.incident_id})
    return build_cs_action_response(affected)
