"""Elastic Security detection rule command handlers (mutations)."""
from __future__ import annotations

import uuid
from dataclasses import asdict

from domain.es_rule import EsRule
from repository.es_rule_repo import es_rule_repo
from utils.dt import utc_now


def create_rule(data: dict) -> dict:
    """Create a new detection rule.

    Args:
        data: Rule creation payload with at least ``name``, ``description``,
              ``type``, ``risk_score``, and ``severity``.

    Returns:
        The newly created rule as a dict.
    """
    now = utc_now()
    rule = EsRule(
        id=str(uuid.uuid4()),
        rule_id=data.get("rule_id", str(uuid.uuid4())),
        name=data.get("name", "Untitled Rule"),
        description=data.get("description", ""),
        type=data.get("type", "query"),
        query=data.get("query", ""),
        language=data.get("language", "kuery"),
        index=data.get("index", ["logs-*", "filebeat-*"]),
        severity=data.get("severity", "medium"),
        risk_score=data.get("risk_score", 50),
        enabled=data.get("enabled", True),
        tags=data.get("tags", []),
        threat=data.get("threat", []),
        author=data.get("author", ["Elastic"]),
        version=1,
        interval=data.get("interval", "5m"),
        from_field=data.get("from", "now-6m"),
        max_signals=data.get("max_signals", 100),
        false_positives=data.get("false_positives", []),
        references=data.get("references", []),
        actions=data.get("actions", []),
        exceptions_list=data.get("exceptions_list", []),
        created_at=now,
        created_by="elastic",
        updated_at=now,
        updated_by="elastic",
        immutable=False,
    )
    es_rule_repo.save(rule)
    return _rule_to_dict(rule)


def update_rule(rule_id: str, data: dict) -> dict | None:
    """Update an existing detection rule.

    Args:
        rule_id: The internal ``id`` of the rule to update.
        data:    Fields to update on the rule.

    Returns:
        Updated rule dict, or None if not found.
    """
    rule = es_rule_repo.get(rule_id)
    if not rule:
        return None

    now = utc_now()
    updatable_fields = (
        "name", "description", "type", "query", "language", "index",
        "severity", "risk_score", "enabled", "tags", "threat", "author",
        "interval", "max_signals", "false_positives", "references",
        "actions", "exceptions_list",
    )
    for field in updatable_fields:
        if field in data:
            setattr(rule, field, data[field])
    if "from" in data:
        rule.from_field = data["from"]

    rule.version += 1
    rule.updated_at = now
    rule.updated_by = "elastic"
    es_rule_repo.save(rule)
    return _rule_to_dict(rule)


def delete_rule(rule_id: str) -> bool:
    """Delete a detection rule by its internal ID.

    Args:
        rule_id: The internal ``id`` of the rule to delete.

    Returns:
        True if the rule existed and was deleted, False otherwise.
    """
    return es_rule_repo.delete(rule_id)


def bulk_action(action: str, rule_ids: list[str] | None = None, query: str | None = None) -> dict:
    """Perform a bulk action on detection rules.

    Args:
        action:   One of ``"enable"``, ``"disable"``, ``"delete"``, ``"export"``.
        rule_ids: List of rule IDs to act on.  If None, ``query`` is used.
        query:    Filter query string (used if ``rule_ids`` is None).

    Returns:
        Summary dict with counts and affected rules.
    """
    rules = _resolve_rules(rule_ids, query)

    if action == "enable":
        for rule in rules:
            rule.enabled = True
            rule.updated_at = utc_now()
            rule.updated_by = "elastic"
            es_rule_repo.save(rule)
        return _bulk_result(rules, action)

    if action == "disable":
        for rule in rules:
            rule.enabled = False
            rule.updated_at = utc_now()
            rule.updated_by = "elastic"
            es_rule_repo.save(rule)
        return _bulk_result(rules, action)

    if action == "delete":
        for rule in rules:
            es_rule_repo.delete(rule.id)
        return _bulk_result(rules, action)

    if action == "export":
        exported = [_rule_to_dict(r) for r in rules]
        return {"exported_count": len(exported), "rules": exported}

    return {"success": False, "message": f"Unknown action: {action}"}


# ── Helpers ──────────────────────────────────────────────────────────────────


def _rule_to_dict(rule: EsRule) -> dict:
    """Convert a rule dataclass to dict, renaming ``from_field`` back to ``from``."""
    d = asdict(rule)
    d["from"] = d.pop("from_field", "now-6m")
    return d


def _resolve_rules(rule_ids: list[str] | None, query: str | None) -> list:
    """Resolve the target rules for a bulk action.

    Args:
        rule_ids: Explicit list of rule IDs.
        query:    Filter string (simple text search on name/tags).

    Returns:
        List of EsRule domain objects.
    """
    if rule_ids:
        return [r for r in es_rule_repo.list_all() if r.id in set(rule_ids)]

    if query:
        lower = query.lower()
        return [
            r for r in es_rule_repo.list_all()
            if lower in r.name.lower() or any(lower in t.lower() for t in r.tags)
        ]

    return list(es_rule_repo.list_all())


def _bulk_result(rules: list, action: str) -> dict:
    """Build a bulk action result envelope.

    Args:
        rules:  List of affected rules.
        action: The action that was performed.

    Returns:
        Result summary dict.
    """
    return {
        "success": True,
        "rules_count": len(rules),
        "rules": [_rule_to_dict(r) for r in rules],
        "action": action,
    }
