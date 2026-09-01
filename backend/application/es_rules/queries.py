"""Elastic Security detection rule query handlers (read-only)."""
from __future__ import annotations

import re

from application.es_rules.commands import _rule_to_dict as _to_response
from domain.es_rule import EsRule
from repository.es_rule_repo import es_rule_repo
from utils.es_pagination import paginate_kibana
from utils.es_response import build_kibana_rules_response


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
    records = [_rule_to_dict(r, listed=True) for r in es_rule_repo.list_all()]

    if filter_str:
        records = _apply_filter(records, filter_str)

    if sort_field:
        reverse = sort_order.lower() == "desc"
        records.sort(key=lambda r: _sort_key(r, sort_field), reverse=reverse)

    page_items, total = paginate_kibana(records, page, per_page)
    return build_kibana_rules_response(page_items, page, per_page, total)


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


def _sort_key(record: dict, sort_field: str) -> tuple[int, float, str]:
    """Resolve a sort field that may name a nested member.

    ``execution_summary.last_execution.date`` is one of the fields this
    endpoint accepts, and a flat lookup found nothing under that name — so
    every rule sorted equal and the list came back in insertion order while
    reporting the sort it was asked for.
    """
    value: object = record
    for part in sort_field.split("."):
        if not isinstance(value, dict):
            value = None
            break
        value = value.get(part)

    # A pair, not the value itself: a missing path used to fall back to `""`,
    # so sorting by a numeric field mixed `int` with `str` and the sort
    # raised. The first member keeps absent values together at one end, the
    # second orders what is there.
    if isinstance(value, bool):
        return (1, float(value), "")
    if isinstance(value, (int, float)):
        return (1, float(value), "")
    if isinstance(value, str):
        return (1, 0.0, value)
    return (0, 0.0, "")


def _rule_to_dict(rule: EsRule, *, listed: bool = False) -> dict:
    """Render a rule as Kibana's ``RuleResponse``.

    Delegates to the command module so reads and writes cannot describe the
    same rule differently. The domain dataclass uses ``from_field`` to avoid
    shadowing the Python keyword; the Elastic API expects ``from``.
    """
    return _to_response(rule, listed=listed)


class UnknownFilterKeyError(ValueError):
    """A saved-object attribute the rules index does not have."""


class UnwrappedFilterError(ValueError):
    """A filter with no saved-object type in front of the key."""


#: Where each saved-object attribute path lives on a rule document.
#: `alert.attributes.params.<x>` is the rule's own body, `alert.attributes.<x>`
#: is the alerting framework's wrapper around it. Measured on 8.15: the two
#: that matter to a console are `params.severity` and `enabled`, and an
#: attribute the index does not have is a 400 rather than an empty page.
_FILTER_KEYS: dict[str, str] = {
    "alert.attributes.enabled": "enabled",
    "alert.attributes.name": "name",
    "alert.attributes.tags": "tags",
    "alert.attributes.params.severity": "severity",
    "alert.attributes.params.risk_score": "risk_score",
    "alert.attributes.params.type": "type",
    "alert.attributes.params.index": "index",
    "alert.attributes.params.rule_id": "rule_id",
    "alert.attributes.params.description": "description",
}

#: `<key> <op> <value>` — KQL's comparison, with the operators 8.15 answers to.
_CLAUSE = re.compile(
    r"^\s*(?P<key>[\w.]+)\s*(?P<op>>=|<=|>|<|:)\s*(?P<value>.+?)\s*$")


def _clause_matches(record: dict, key: str, op: str, value: str) -> bool:
    """One `key: value` against one rule."""
    field = _FILTER_KEYS[key]
    held = record.get(field)
    wanted = value.strip().strip('"').strip("'")
    if wanted == "*":
        return held not in (None, "", [])
    if isinstance(held, list):
        return any(str(item).lower() == wanted.lower() for item in held)
    if op == ":":
        if isinstance(held, bool):
            return str(held).lower() == wanted.lower()
        return str(held).lower() == wanted.lower()
    try:
        left, right = float(held), float(wanted)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    return {">=" : left >= right, "<=": left <= right,
            ">": left > right, "<": left < right}[op]


def _apply_filter(records: list[dict], filter_str: str) -> list[dict]:
    """Apply Kibana's saved-object filter to rule records.

    This read `enabled` by looking for the word anywhere in the string and
    turned everything else into a text search over name and tags — so
    `alert.attributes.params.severity: critical`, which is what the console's
    own severity dropdown sends, matched nothing and emptied the table for
    every value. 8.15 answers that filter with the rules of that severity,
    and refuses an attribute the index does not have rather than answering
    an empty page.

    Raises:
        UnwrappedFilterError: A filter with no `<type>.attributes.` key.
        UnknownFilterKeyError: A key the rules index does not carry.
    """
    kept = records
    for part in re.split(r"\s+AND\s+", filter_str.strip(), flags=re.IGNORECASE):
        clause = _CLAUSE.match(part)
        if not clause or "." not in clause.group("key"):
            raise UnwrappedFilterError(part.strip())
        key = clause.group("key")
        if key not in _FILTER_KEYS:
            raise UnknownFilterKeyError(key)
        kept = [
            r for r in kept
            if _clause_matches(r, key, clause.group("op"), clause.group("value"))
        ]
    return kept
