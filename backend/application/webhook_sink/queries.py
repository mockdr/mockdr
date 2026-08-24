"""Read-only application queries for the webhook sink."""
from __future__ import annotations

from repository.webhook_sink_repo import webhook_sink_repo
from utils.serde import record_dict


def list_captured(limit: int = 100) -> dict:
    """Return the most recent captured webhook deliveries.

    Args:
        limit: Maximum number of entries to return.  Defaults to 100.

    Returns:
        Dict with ``data`` list and ``pagination.totalItems`` count.
    """
    all_entries = webhook_sink_repo.list_recent()
    limited = all_entries[:limit]
    return {
        "data": [record_dict(e) for e in limited],
        "pagination": {"totalItems": len(all_entries)},
    }
