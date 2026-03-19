"""CrowdStrike Falcon Quarantine command handlers (mutations)."""
from __future__ import annotations

from repository.cs_quarantine_repo import cs_quarantine_repo
from utils.cs_response import build_cs_action_response, build_cs_error_response
from utils.dt import utc_now


def action_quarantined_files(ids: list[str], action: str) -> dict:
    """Apply an action (release, delete, unquarantine) to quarantined files.

    Args:
        ids:    List of quarantined file IDs to act on.
        action: Action name — ``release``, ``delete``, or ``unquarantine``.

    Returns:
        CS action response envelope with affected resource IDs.
    """
    if action not in ("release", "delete", "unquarantine"):
        return build_cs_error_response(400, f"Invalid action: {action}")

    state_map = {
        "release": "released",
        "delete": "deleted",
        "unquarantine": "released",
    }
    new_state = state_map[action]
    now = utc_now()

    affected: list[dict] = []
    for file_id in ids:
        qf = cs_quarantine_repo.get(file_id)
        if not qf:
            continue
        qf.state = new_state
        qf.date_updated = now
        cs_quarantine_repo.save(qf)
        affected.append({"id": file_id})

    return build_cs_action_response(affected)
