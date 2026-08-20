"""Serialisation for Elastic Security Cases resources.

The stored dataclass uses snake_case for the comment/alert totals, but
Kibana's ``CaseRt`` declares them camelCase (``totalComment``, ``totalAlerts``,
``totalEvents``). Emitting the internal names meant a client written against a
real Kibana read ``undefined`` for all three.
"""
from __future__ import annotations

from typing import Any

# Internal dataclass field -> the name Kibana's CaseRt declares.
_CASE_FIELD_ALIASES: dict[str, str] = {
    "total_comment": "totalComment",
    "total_alerts": "totalAlerts",
    "total_events": "totalEvents",
}


def serialise_case(record: dict[str, Any]) -> dict[str, Any]:
    """Rename a case dict's internal fields to their Kibana-facing names."""
    return {_CASE_FIELD_ALIASES.get(key, key): value for key, value in record.items()}


def status_counts(records: list[dict[str, Any]]) -> dict[str, int]:
    """Count cases per status for the ``_find`` envelope."""
    counts: dict[str, int] = {"open": 0, "in-progress": 0, "closed": 0}
    for record in records:
        status = record.get("status", "")
        if status in counts:
            counts[status] += 1
    return counts
