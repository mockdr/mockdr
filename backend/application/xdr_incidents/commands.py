"""Cortex XDR Incident command handlers (mutations)."""
from __future__ import annotations

from repository.xdr_incident_repo import xdr_incident_repo
from utils.xdr_response import build_xdr_reply


def update_incident(incident_id: str, update_data: dict) -> dict | None:
    """Update an incident's status, severity, assignee, or manual_score.

    Args:
        incident_id: The incident identifier.
        update_data: Dict with fields to update (``status``, ``severity``,
            ``assigned_user_mail``, ``assigned_user_pretty_name``,
            ``manual_score``).

    Returns:
        XDR reply confirming success, or None if incident not found.
    """
    incident = xdr_incident_repo.get(incident_id)
    if not incident:
        return None

    allowed = {
        "status", "severity", "assigned_user_mail",
        "assigned_user_pretty_name", "manual_score",
    }
    for key, value in update_data.items():
        if key in allowed and hasattr(incident, key):
            setattr(incident, key, value)

    xdr_incident_repo.save(incident)
    return build_xdr_reply(True)
