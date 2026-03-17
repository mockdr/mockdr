"""Sentinel analytics rule command handlers."""
from __future__ import annotations

import uuid

from domain.sentinel.alert_rule import SentinelAlertRule
from repository.sentinel.alert_rule_repo import sentinel_alert_rule_repo


def create_or_update_rule(rule_id: str, properties: dict) -> SentinelAlertRule:
    """Create or update an analytics rule.

    Args:
        rule_id:    Rule resource name.
        properties: ARM properties bag.

    Returns:
        The created/updated rule.
    """
    existing = sentinel_alert_rule_repo.get(rule_id)

    if existing:
        for key in ("displayName", "description", "enabled", "severity",
                     "query", "tactics", "techniques", "kind"):
            if key in properties:
                attr = key[0].lower() + key[1:]
                # Map camelCase to snake_case for known fields
                snake = {"displayName": "display_name", "queryFrequency": "query_frequency",
                         "queryPeriod": "query_period", "triggerOperator": "trigger_operator",
                         "triggerThreshold": "trigger_threshold", "productFilter": "product_filter"
                         }.get(key, attr)
                setattr(existing, snake, properties[key])
        existing.etag = uuid.uuid4().hex[:8]
        sentinel_alert_rule_repo.save(existing)
        return existing

    rule = SentinelAlertRule(
        rule_id=rule_id,
        display_name=properties.get("displayName", rule_id),
        description=properties.get("description", ""),
        kind=properties.get("kind", "Scheduled"),
        enabled=properties.get("enabled", True),
        severity=properties.get("severity", "Medium"),
        query=properties.get("query", ""),
        tactics=properties.get("tactics", []),
        techniques=properties.get("techniques", []),
        product_filter=properties.get("productFilter", ""),
        etag=uuid.uuid4().hex[:8],
    )
    sentinel_alert_rule_repo.save(rule)
    return rule


def delete_rule(rule_id: str) -> bool:
    """Delete an analytics rule."""
    return sentinel_alert_rule_repo.delete(rule_id)
