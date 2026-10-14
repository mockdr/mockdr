"""Bring a snapshot written by an older release up to this one's vocabulary.

A record whose *shape* changed fails to construct on import, and the
persistence layer quarantines the snapshot rather than serve a hollowed-out
store. A record whose *values* were renamed constructs perfectly well and
used to be served as it was: a 2.5 snapshot restored under 2.6 kept Cortex
endpoints ``isolated`` — a value 2.6 never writes, never settles out of and
that no ``AGENT_*`` comparison in a client matches — and SentinelOne threats
``killed``, outside the swagger enum ``mitigationStatuses=`` filters on.

Each rule maps a value an earlier release wrote to the one this release
writes for the same state. The rules only ever match values the current
code cannot produce, so applying them to a current snapshot changes nothing.
"""
from __future__ import annotations

from typing import Any

#: 2.5 wrote `isolated` / `unisolated`; 2.6 speaks Cortex's AGENT_* states.
_XDR_ISOLATION = {"isolated": "AGENT_ISOLATED", "unisolated": "AGENT_UNISOLATED"}

#: 2.5 wrote the action's past tense into threatInfo.mitigationStatus (its
#: `_MITIGATION_MAP`): kill -> killed, quarantine -> quarantined,
#: remediate -> remediated, rollback-remediation -> rollback, un-quarantine
#: -> active. 2.6 writes the swagger enum the way `record_mitigation` does.
_S1_MITIGATION = {
    "killed": "mitigated",
    "quarantined": "mitigated",
    "remediated": "mitigated",
    "rollback": "mitigated",
    "active": "not_mitigated",
}

#: 2.5 spelled XQL status pending / running / completed / failed; the wire,
#: and 2.6, say PENDING / SUCCESS / FAIL.
_XQL_STATUS = {"pending": "PENDING", "running": "PENDING", "completed": "SUCCESS",
               "failed": "FAIL"}


def _xdr_endpoint(record: dict) -> bool:
    old = record.get("is_isolated")
    new = _XDR_ISOLATION.get(str(old).lower()) if isinstance(old, str) else None
    if new is None:
        return False
    record["is_isolated"] = new
    return True


def _threat(record: dict) -> bool:
    info = record.get("threatInfo")
    if not isinstance(info, dict):
        return False
    new = _S1_MITIGATION.get(str(info.get("mitigationStatus", "")))
    if new is None:
        return False
    info["mitigationStatus"] = new
    info["mitigationStatusDescription"] = new.replace("_", " ").title()
    return True


def _xdr_alert(record: dict) -> bool:
    """2.6 seeded ``internal_id`` as an ``INT_<hex>`` string; Cortex sends an integer."""
    old = record.get("internal_id")
    if not isinstance(old, str):
        return False
    hex_part = old[4:11] if old.startswith("INT_") else ""
    try:
        record["internal_id"] = int(hex_part, 16) if hex_part else int(old or 0)
    except ValueError:
        record["internal_id"] = 0
    return True


def _xql_query(record: dict) -> bool:
    new = _XQL_STATUS.get(str(record.get("status", "")))
    if new is None:
        return False
    record["status"] = new
    return True


_RULES = {
    "xdr_endpoints": _xdr_endpoint,
    "threats": _threat,
    "xdr_xql_queries": _xql_query,
    "xdr_alerts": _xdr_alert,
}


def migrate_record(collection: str, record: Any) -> bool:  # noqa: ANN401 - any record shape
    """Rewrite *record* in place to this release's vocabulary; whether anything changed."""
    rule = _RULES.get(collection)
    return bool(rule and isinstance(record, dict) and rule(record))
