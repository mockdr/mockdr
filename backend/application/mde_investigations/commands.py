"""Microsoft Defender for Endpoint Investigation command handlers (mutations)."""
from __future__ import annotations

from dataclasses import asdict

from repository.mde_investigation_repo import mde_investigation_repo


def collect_investigation(investigation_id: str) -> dict | None:
    """Trigger evidence collection for an investigation.

    Updates the investigation state to ``"Running"`` and sets its end time.

    Args:
        investigation_id: GUID of the investigation to collect.

    Returns:
        Updated investigation dict, or None if not found.
    """
    investigation = mde_investigation_repo.get(investigation_id)
    if not investigation:
        return None
    investigation.state = "Running"
    investigation.endTime = ""
    investigation.statusDetails = "CollectingEvidence"
    mde_investigation_repo.save(investigation)
    return asdict(investigation)
