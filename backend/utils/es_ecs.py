"""Render Elastic Security alerts as the documents a real cluster stores.

The stored dataclass uses flat snake_case names (``signal_rule_name``,
``hostname``, ``process_pid``). Real alert documents are ECS: ``host.name``,
``process.pid``, ``file.hash.sha256``, ``@timestamp`` — and the rule metadata
lives under ``kibana.alert.rule.*`` in the current index or ``signal.rule.*``
in the legacy one. **Every** field name differed, so a query written against a
real cluster matched nothing here, and the two index families returned
byte-identical documents though their schemas differ substantially.

The dataclass stays internal; this is the API representation, in the same way
:mod:`utils.es_case_serde` handles Kibana cases.
"""
from __future__ import annotations

from typing import Any

__all__ = ["ecs_field_for", "to_ecs_document"]

# Index families whose documents use the current kibana.alert.* schema.
_ALERTS_PREFIX = ".alerts-security"


def _put(document: dict[str, Any], path: str, value: Any) -> None:
    """Set a dotted path, creating the intermediate objects."""
    if value in (None, ""):
        return
    parts = path.split(".")
    cursor = document
    for part in parts[:-1]:
        nxt = cursor.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cursor[part] = nxt
        cursor = nxt
    cursor[parts[-1]] = value


#: Internal dataclass field -> ECS path shared by both index families.
_COMMON: dict[str, str] = {
    "timestamp": "@timestamp",
    "agent_id": "agent.id",
    "hostname": "host.name",
    "host_ip": "host.ip",
    "host_os": "host.os.name",
    "process_name": "process.name",
    "process_executable": "process.executable",
    "process_args": "process.args",
    "process_pid": "process.pid",
    "user_name": "user.name",
    "file_name": "file.name",
    "file_path": "file.path",
    "file_hash_sha256": "file.hash.sha256",
    "threat_tactic_name": "threat.tactic.name",
    "threat_tactic_id": "threat.tactic.id",
    "threat_technique_name": "threat.technique.name",
    "threat_technique_id": "threat.technique.id",
    "tags": "tags",
}

#: Rule and workflow fields, which differ between the two index families.
_ALERTS_SCHEMA: dict[str, str] = {
    "id": "kibana.alert.uuid",
    "signal_rule_id": "kibana.alert.rule.uuid",
    "signal_rule_name": "kibana.alert.rule.name",
    "signal_rule_severity": "kibana.alert.severity",
    "signal_rule_risk_score": "kibana.alert.risk_score",
    "signal_status": "kibana.alert.status",
    "workflow_status": "kibana.alert.workflow_status",
    "assignees": "kibana.alert.workflow_assignee_ids",
}

_SIGNALS_SCHEMA: dict[str, str] = {
    "id": "signal.rule.id",
    "signal_rule_id": "signal.rule.rule_id",
    "signal_rule_name": "signal.rule.name",
    "signal_rule_severity": "signal.rule.severity",
    "signal_rule_risk_score": "signal.rule.risk_score",
    "signal_status": "signal.status",
    "workflow_status": "signal.status",
    "assignees": "signal.assignees",
}


def _schema_for(index: str) -> dict[str, str]:
    return _ALERTS_SCHEMA if _ALERTS_PREFIX in index.lower() else _SIGNALS_SCHEMA


def ecs_field_for(field: str, index: str) -> str:
    """Map an internal field name to its ECS path for *index*.

    Lets a query written against the real field names reach the stored data
    without duplicating the mapping in the query layer.
    """
    schema = _schema_for(index)
    return schema.get(field) or _COMMON.get(field, field)


def to_ecs_document(record: dict[str, Any], index: str) -> dict[str, Any]:
    """Render one stored alert as the ECS document *index* would hold."""
    schema = _schema_for(index)
    document: dict[str, Any] = {}

    for field, value in record.items():
        path = schema.get(field) or _COMMON.get(field)
        if path is None:
            # Anything without a mapping is carried through untouched rather
            # than dropped, so nothing silently disappears from the document.
            document.setdefault(field, value)
            continue
        _put(document, path, value)

    # Fields every alert document carries that the dataclass has no slot for.
    _put(document, "event.kind", "signal")
    _put(document, "event.category", ["intrusion_detection"])
    _put(document, "ecs.version", "8.11.0")
    if _ALERTS_PREFIX in index.lower():
        _put(document, "kibana.alert.rule.parameters", {})
        _put(document, "kibana.space_ids", ["default"])
    return document
