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


#: What a case was opened from is mockdr's own bookkeeping — `totalAlerts` is
#: derived from it. Kibana carries no such member; the alerts on a case live
#: in its comments.
_CASE_INTERNAL_FIELDS: frozenset[str] = frozenset({"alert_ids"})

#: Members every Kibana case carries that the dataclass has no slot for. A
#: client reading `case.comments` or `case.customFields` found nothing here
#: (measured against Kibana 8.15).
_CASE_DEFAULTS: dict[str, Any] = {
    "category": None,
    "comments": [],
    "customFields": [],
    "duration": None,
    "external_service": None,
}


#: The user object Kibana serves, measured against 8.15: a username, and two
#: members that are null unless a real user profile fills them. mockdr wrote
#: an invented "Elastic Admin" into `full_name` and left `email` out
#: altogether, so a client reading either found something no Kibana serves.
KIBANA_USER: dict[str, Any] = {"email": None, "full_name": None, "username": "elastic"}


def serialise_case(record: dict[str, Any]) -> dict[str, Any]:
    """Render a case the way Kibana's ``CaseRt`` does.

    Internal names become the ones Kibana declares, mockdr's own bookkeeping
    is dropped, and the members every case carries are filled in.
    """
    rendered = {
        _CASE_FIELD_ALIASES.get(key, key): value
        for key, value in record.items()
        if key not in _CASE_INTERNAL_FIELDS
    }
    for key, value in _CASE_DEFAULTS.items():
        rendered.setdefault(key, list(value) if isinstance(value, list) else value)
    return rendered


def status_counts(records: list[dict[str, Any]]) -> dict[str, int]:
    """Count cases per status for the ``_find`` envelope."""
    counts: dict[str, int] = {"open": 0, "in-progress": 0, "closed": 0}
    for record in records:
        status = record.get("status", "")
        if status in counts:
            counts[status] += 1
    return counts


#: Members every Kibana comment carries that the dataclass has no slot for.
_COMMENT_DEFAULTS: dict[str, Any] = {
    "owner": "securitySolution",
    "pushed_at": None,
    "pushed_by": None,
}


def serialise_comment(record: dict[str, Any]) -> dict[str, Any]:
    """Render a case comment the way Kibana's ``CommentResponse`` does.

    ``case_id`` is dropped — the case is identified by the request path, and no
    real comment object carries it — and the members every comment has are
    filled in.
    """
    rendered = {k: v for k, v in record.items() if k != "case_id"}
    for key, value in _COMMENT_DEFAULTS.items():
        rendered.setdefault(key, value)
    return rendered
