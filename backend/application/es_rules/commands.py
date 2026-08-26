"""Elastic Security detection rule command handlers (mutations)."""
from __future__ import annotations

import uuid
from dataclasses import replace

from domain.es_rule import EsRule
from repository.es_rule_repo import es_rule_repo
from utils.dt import utc_now
from utils.serde import record_dict


class UnknownBulkActionError(ValueError):
    """Raised for a bulk action Kibana does not define.

    An unknown action used to return ``200 {"success": false}``, so a typo in
    a playbook read as a successful call.
    """


def create_rule(data: dict, author: str = "elastic") -> dict:
    """Create a new detection rule.

    Args:
        data:   Rule creation payload with at least ``name``, ``description``,
                ``type``, ``risk_score``, and ``severity``.
        author: The caller. Kibana records who wrote a rule, and every write
                here used to say `elastic` — the superuser — whoever had
                called, which is the same failure `/privileges` had when it
                reported the caller as `elastic` too.

    Returns:
        The newly created rule as a dict.
    """
    now = utc_now()
    rule = replace(
        _from_body(data, str(uuid.uuid4()), str(uuid.uuid4())),
        created_at=now,
        created_by=author,
        updated_at=now,
        updated_by=author,
    )
    es_rule_repo.save(rule)
    return _rule_to_dict(rule)


def update_rule(rule: EsRule, data: dict, author: str = "elastic") -> dict:
    """Replace a rule from a full ``RuleUpdateProps`` body.

    PUT replaces: a member the body leaves out is gone afterwards, which is
    how a client resets a rule to a known state. Merging instead kept a
    ``note`` the client had just removed.

    What PUT does *not* touch is the rule's identity, when it was created,
    whether it is enabled, or its author-set ``version`` — Kibana keeps all
    of those unless the body names them.
    """
    before = _parameters(rule)
    replaced = replace(
        _from_body(data, rule.id, rule.rule_id),
        created_at=rule.created_at,
        created_by=rule.created_by,
        enabled=data.get("enabled", rule.enabled),
        version=data.get("version", rule.version),
        revision=rule.revision,
        last_execution=rule.last_execution,
        updated_at=utc_now(),
        updated_by=author,
    )
    _count_revision(replaced, before)
    es_rule_repo.save(replaced)
    return _rule_to_dict(replaced)


def patch_rule(rule: EsRule, data: dict, author: str = "elastic") -> dict:
    """Apply a partial ``RulePatchProps`` body to a rule.

    PATCH touches only what the body names, and counts as a modification only
    if a parameter actually changed — enabling a rule, or re-sending a value
    it already had, leaves ``revision`` where it was.
    """
    before = _parameters(rule)
    for field in _UPDATABLE_FIELDS:
        if field in data:
            setattr(rule, field, data[field])
    if "from" in data:
        rule.from_field = data["from"]
    if "version" in data:
        rule.version = data["version"]
    rule.optional_members = {**rule.optional_members, **optional_members_from(data)}

    _count_revision(rule, before)
    rule.updated_at = utc_now()
    rule.updated_by = author
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


def bulk_action(
    action: str,
    rule_ids: list[str] | None = None,
    query: str | None = None,
    author: str = "elastic",
) -> dict:
    """Perform a bulk action on detection rules.

    Args:
        action:   One of ``"enable"``, ``"disable"``, ``"delete"``, ``"export"``.
        rule_ids: List of rule IDs to act on.  If None, ``query`` is used.
        query:    Filter query string (used if ``rule_ids`` is None).
        author:   The caller, recorded on every rule the action touches.

    Returns:
        Summary dict with counts and affected rules.
    """
    rules = _resolve_rules(rule_ids, query)

    if action == "enable":
        for rule in rules:
            rule.enabled = True
            rule.updated_at = utc_now()
            rule.updated_by = author
            es_rule_repo.save(rule)
        return _bulk_result(rules, action)

    if action == "disable":
        for rule in rules:
            rule.enabled = False
            rule.updated_at = utc_now()
            rule.updated_by = author
            es_rule_repo.save(rule)
        return _bulk_result(rules, action)

    if action == "delete":
        for rule in rules:
            es_rule_repo.delete(rule.id)
        return _bulk_result(rules, action)

    if action == "duplicate":
        copies = []
        for rule in rules:
            clone = replace(
                rule,
                id=str(uuid.uuid4()),
                rule_id=str(uuid.uuid4()),
                name=f"{rule.name} [Duplicate]",
                created_at=utc_now(),
                created_by=author,
                updated_at=utc_now(),
                updated_by=author,
            )
            es_rule_repo.save(clone)
            copies.append(clone)
        return _bulk_result(copies, action)

    if action == "export":
        exported = [_rule_to_dict(r) for r in rules]
        return {"exported_count": len(exported), "rules": exported}

    msg = f"Unknown action: {action}"
    raise UnknownBulkActionError(msg)


# ── Helpers ──────────────────────────────────────────────────────────────────


#: Members Kibana echoes only when the client set one. Measured on 8.15: a
#: rule created with the required fields alone carries none of these, so
#: filling them in told a client about a `note`, a `throttle` and a timeline
#: the product would not have mentioned.
_OPTIONAL_MEMBERS = (
    "building_block_type", "filters", "investigation_fields", "license",
    "meta", "note", "throttle", "timeline_id", "timeline_title",
)


#: Members every RuleResponse carries that the dataclass has no slot for.
#: `to` in particular is mandatory and its absence broke clients that read the
#: from/to pair to compute a rule's look-back window.
_RULE_RESPONSE_DEFAULTS: dict = {
    "to": "now",
    "rule_source": {"type": "internal"},
    "output_index": "",
    "related_integrations": [],
    "required_fields": [],
    "setup": "",
    "severity_mapping": [],
    "risk_score_mapping": [],
    "exceptions_list": [],
    "actions": [],
    "immutable": False,
}


def _rule_to_dict(rule: EsRule, *, listed: bool = False) -> dict:
    """Render a rule as Kibana's ``RuleResponse``.

    ``from_field`` is renamed back to ``from``, and the members every real
    RuleResponse carries are filled in — nineteen were missing, including the
    mandatory ``to``. The optional ones are echoed only if the client set
    them, which is what the product does.

    ``execution_summary`` follows the product's own asymmetry: a listing
    carries the key for every rule and leaves it ``null`` where nothing has
    run, while a single rule that has never run does not carry the key at
    all. A client reading rule health has to survive both.
    """
    d = record_dict(rule)
    d["from"] = d.pop("from_field", "now-6m")
    last_execution = d.pop("last_execution", None)
    d.update(d.pop("optional_members", {}))
    for key, value in _RULE_RESPONSE_DEFAULTS.items():
        d.setdefault(key, value.copy() if isinstance(value, (dict, list)) else value)
    if last_execution:
        d["execution_summary"] = {"last_execution": last_execution}
    elif listed:
        d["execution_summary"] = None
    return d


#: The fields a rule's body can carry into the dataclass.
_UPDATABLE_FIELDS = (
    "name", "description", "type", "query", "language", "index",
    "severity", "risk_score", "enabled", "tags", "threat", "author",
    "interval", "max_signals", "false_positives", "references",
    "actions", "exceptions_list",
)


#: What a revision does *not* count. Kibana raises `revision` when a rule's
#: parameters change; enabling one is a separate operation, and the audit
#: members move on every write by definition.
_NOT_A_PARAMETER = frozenset({
    "enabled", "revision", "updated_at", "updated_by", "last_execution",
})


def _parameters(rule: EsRule) -> dict:
    """The members a change to which is what `revision` counts."""
    return {k: v for k, v in record_dict(rule).items() if k not in _NOT_A_PARAMETER}


def _count_revision(rule: EsRule, before: dict) -> None:
    """Raise ``revision`` if this write actually changed the rule."""
    if _parameters(rule) != before:
        rule.revision += 1


def _from_body(data: dict, rule_id: str, public_rule_id: str) -> EsRule:
    """Build a rule from a create/replace body, defaults and all."""
    return EsRule(
        id=rule_id,
        rule_id=data.get("rule_id", public_rule_id),
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
        version=data.get("version", 1),
        interval=data.get("interval", "5m"),
        from_field=data.get("from", "now-6m"),
        max_signals=data.get("max_signals", 100),
        false_positives=data.get("false_positives", []),
        references=data.get("references", []),
        actions=data.get("actions", []),
        exceptions_list=data.get("exceptions_list", []),
        immutable=False,
        optional_members=optional_members_from(data),
    )


def optional_members_from(data: dict) -> dict:
    """Pick out the members a rule carries only because the client sent them."""
    return {key: data[key] for key in _OPTIONAL_MEMBERS if key in data}


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


#: Where each action's results land in the response. Kibana groups them by
#: what happened to the rule, not by which action asked.
_ACTION_BUCKET = {
    "enable": "updated",
    "disable": "updated",
    "edit": "updated",
    "delete": "deleted",
    "duplicate": "created",
}


def _bulk_result(rules: list, action: str) -> dict:
    """Build a bulk action result envelope.

    Kibana returns ``attributes.results`` grouped into created/updated/deleted/
    skipped plus an ``attributes.summary`` of counts. There is no top-level
    ``rules`` key, so a client reading the documented shape found nothing.

    Args:
        rules:  List of affected rules.
        action: The action that was performed.

    Returns:
        Result summary dict.
    """
    payload = [_rule_to_dict(r) for r in rules]
    results: dict[str, list] = {
        "updated": [], "created": [], "deleted": [], "skipped": [],
    }
    results[_ACTION_BUCKET.get(action, "updated")] = payload
    return {
        "success": True,
        "rules_count": len(rules),
        "attributes": {
            "results": results,
            "summary": {
                "failed": 0,
                "succeeded": len(rules),
                "skipped": 0,
                "total": len(rules),
            },
        },
    }
