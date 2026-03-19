"""Elastic Security detection rule query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from domain.es_rule import EsRule
from repository.es_rule_repo import es_rule_repo
from utils.es_pagination import paginate_kibana
from utils.es_response import build_kibana_list_response


def find_rules(
    page: int = 1,
    per_page: int = 20,
    sort_field: str | None = None,
    sort_order: str = "asc",
    filter_str: str | None = None,
) -> dict:
    """Find detection rules with optional filtering and Kibana-style pagination.

    Args:
        page:        Page number (1-based).
        per_page:    Number of items per page.
        sort_field:  Field name to sort by, or None.
        sort_order:  Sort direction (``"asc"`` or ``"desc"``).
        filter_str:  Simple filter string — matches against rule name, tags,
                     and enabled status.

    Returns:
        Kibana paginated list response.
    """
    records = [_rule_to_dict(r) for r in es_rule_repo.list_all()]

    if filter_str:
        records = _apply_filter(records, filter_str)

    if sort_field:
        reverse = sort_order.lower() == "desc"
        records.sort(key=lambda r: r.get(sort_field, ""), reverse=reverse)

    page_items, total = paginate_kibana(records, page, per_page)
    return build_kibana_list_response(page_items, page, per_page, total)


def get_rule(rule_id: str) -> dict | None:
    """Get a single rule by its internal ID.

    Args:
        rule_id: The internal ``id`` of the rule.

    Returns:
        Rule dict, or None if not found.
    """
    rule = es_rule_repo.get(rule_id)
    if not rule:
        return None
    return _rule_to_dict(rule)


def get_rule_by_rule_id(rule_id: str) -> dict | None:
    """Get a single rule by its ``rule_id`` field.

    Args:
        rule_id: The public ``rule_id`` of the rule.

    Returns:
        Rule dict, or None if not found.
    """
    rule = es_rule_repo.get_by_rule_id(rule_id)
    if not rule:
        return None
    return _rule_to_dict(rule)


# ── Helpers ──────────────────────────────────────────────────────────────────


def get_tags() -> list[str]:
    """Return all unique tags across all detection rules.

    Returns:
        Sorted list of unique tag strings.
    """
    tags: set[str] = set()
    for rule in es_rule_repo.list_all():
        tags.update(rule.tags)
    return sorted(tags)


def _rule_to_dict(rule: EsRule) -> dict:
    """Convert a rule dataclass to dict, renaming ``from_field`` back to ``from``.

    The domain dataclass uses ``from_field`` to avoid shadowing the Python
    keyword; the Elastic API expects ``from``.
    """
    d = asdict(rule)
    d["from"] = d.pop("from_field", "now-6m")
    return d


def _apply_filter(records: list[dict], filter_str: str) -> list[dict]:
    """Apply a simple text filter to rule records.

    Searches rule name and tags for the filter string (case-insensitive).
    Also handles ``alert.attributes.enabled: true/false``.
    """
    lower = filter_str.lower().strip()

    # Handle enabled status filter.
    if "enabled" in lower:
        if "true" in lower:
            return [r for r in records if r.get("enabled") is True]
        if "false" in lower:
            return [r for r in records if r.get("enabled") is False]

    # Text search across name and tags.
    return [
        r for r in records
        if lower in r.get("name", "").lower()
        or any(lower in t.lower() for t in r.get("tags", []))
    ]
