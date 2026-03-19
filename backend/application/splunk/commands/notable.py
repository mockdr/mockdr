"""Splunk notable event command handlers."""
from __future__ import annotations

import time

from repository.splunk.notable_event_repo import notable_event_repo

_STATUS_LABELS: dict[str, str] = {
    "1": "New",
    "2": "In Progress",
    "3": "Pending",
    "4": "Resolved",
    "5": "Closed",
}


def update_notable(
    ruleUIDs: list[str] | None = None,  # noqa: N803
    newUrgency: str = "",  # noqa: N803
    status: str = "",
    newOwner: str = "",  # noqa: N803
    comment: str = "",
    **kwargs: object,
) -> dict:
    """Update one or more notable events.

    Matches the ``POST /services/notable_update`` contract used by XSOAR.

    Args:
        ruleUIDs:    List of notable event IDs to update.
        newUrgency:  New urgency value.
        status:      New status code (1-5).
        newOwner:    New owner.
        comment:     Comment to add.
        **kwargs:    Additional fields (ignored).

    Returns:
        Success response dict.
    """
    if not ruleUIDs:
        return {"success": False, "message": "No event IDs provided"}

    updated = 0
    for event_id in ruleUIDs:
        notable = notable_event_repo.get(event_id)
        if not notable:
            continue

        if status:
            notable.status = status
            notable.status_label = _STATUS_LABELS.get(status, notable.status_label)
        if newUrgency:
            notable.urgency = newUrgency
        if newOwner:
            notable.owner = newOwner
        if comment:
            notable.comment = comment
            notable.status_history.append({
                "time": str(time.time()),
                "status": notable.status,
                "owner": notable.owner,
                "comment": comment,
            })

        notable_event_repo.save(notable)
        updated += 1

    return {"success": True, "message": f"Updated {updated} notable event(s)"}
