"""Sentinel analytics rule query handlers (read-only)."""
from __future__ import annotations

from domain.sentinel.alert_rule import SentinelAlertRule
from repository.sentinel.alert_rule_repo import sentinel_alert_rule_repo
from utils.sentinel.response import build_arm_list, build_arm_resource


def _rule_to_arm(rule: SentinelAlertRule) -> dict:
    """Convert a SentinelAlertRule to ARM format."""
    props: dict = {
        "displayName": rule.display_name,
        "description": rule.description,
        "enabled": rule.enabled,
        "severity": rule.severity,
        "tactics": rule.tactics,
        "techniques": rule.techniques,
    }
    if rule.kind == "Scheduled":
        props.update({
            "query": rule.query,
            "queryFrequency": rule.query_frequency,
            "queryPeriod": rule.query_period,
            "triggerOperator": rule.trigger_operator,
            "triggerThreshold": rule.trigger_threshold,
        })
    elif rule.kind == "MicrosoftSecurityIncidentCreation":
        props["productFilter"] = rule.product_filter

    result = build_arm_resource("alertRules", rule.rule_id, props, etag=rule.etag)
    result["kind"] = rule.kind
    return result


def list_alert_rules() -> dict:
    """Return all analytics rules in ARM format."""
    rules = sentinel_alert_rule_repo.list_all()
    items = [_rule_to_arm(r) for r in rules]
    return build_arm_list(items)


def get_alert_rule(rule_id: str) -> dict | None:
    """Return a single analytics rule."""
    rule = sentinel_alert_rule_repo.get(rule_id)
    if not rule:
        return None
    return _rule_to_arm(rule)
