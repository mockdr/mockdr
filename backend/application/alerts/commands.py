
from application.webhooks import commands as webhook_commands
from domain.webhook import ALERT_UPDATED
from repository.alert_repo import alert_repo
from repository.store import store
from repository.user_repo import user_repo
from utils.dt import utc_now
from utils.id_gen import new_id
from utils.serde import record_dict


def set_analyst_verdict(verdict: str, ids: list[str], actor_user_id: str | None = None) -> dict:
    """Set the analyst verdict on a list of alerts.

    Implements POST /cloud-detection/alerts/analyst-verdict.

    Args:
        verdict: Verdict string (e.g. ``"TRUE_POSITIVE"``).
        ids: List of alert IDs to update.
        actor_user_id: ID of the acting user, if authenticated.

    Returns:
        Dict with ``data.affected`` indicating how many alerts were updated.
    """
    affected = 0
    for alert_id in ids:
        alert = alert_repo.get(alert_id)
        if not alert:
            continue
        alert.alertInfo["analystVerdict"] = verdict
        alert.alertInfo["updatedAt"] = utc_now()
        alert_repo.save(alert)
        webhook_commands.fire_event(ALERT_UPDATED, record_dict(alert))
        affected += 1
    return {"data": {"affected": affected}}


def _full_name(user_id: str | None) -> str:
    """The acting user's full name, as the rule document spells its author."""
    if not user_id:
        return ""
    user = user_repo.get(user_id)
    return getattr(user, "fullName", "") if user else ""


def create_star_rule(body: dict, user_id: str | None) -> dict:
    """Create a STAR custom detection rule.

    Implements POST /cloud-detection/rules.

    Args:
        body: Request body with rule definition (``data`` wrapper accepted).
        user_id: ID of the creating user.

    Returns:
        Dict with ``data`` containing the new rule.
    """
    data = body.get("data") or body
    rule_id = new_id()
    now = utc_now()
    rule = {
        "id": rule_id,
        "name": data.get("name", ""),
        "description": data.get("description", ""),
        "queryType": data.get("queryType", "events"),
        "queryLang": data.get("queryLang", "1.0"),
        "s1ql": data.get("s1ql", ""),
        "severity": data.get("severity", "Medium"),
        "scopeLevel": data.get("scopeLevel", "site"),
        "siteIds": data.get("siteIds", []),
        "groupIds": data.get("groupIds", []),
        "accountIds": data.get("accountIds", []),
        "treatAsThreat": data.get("treatAsThreat", "UNDEFINED"),
        "status": data.get("status", "Active"),
        "expirationMode": data.get("expirationMode", "Permanent"),
        "expiration": data.get("expiration"),
        "networkQuarantine": data.get("networkQuarantine", False),
        # Documented on the create body and kept by nothing, so a rule made
        # from a template answered without the template it came from.
        "templateRuleId": data.get("templateRuleId"),
        "createdAt": now,
        "updatedAt": now,
        # The swagger reads "the full name of the user that created the rule"
        # for `creator` and "the ID" for `creatorId`; both were the id here,
        # so a rule made through the API named its author differently from
        # every rule this mock seeds.
        "creator": _full_name(user_id),
        "creatorId": user_id or "",
        "updaterId": user_id or "",
        "scope": data.get("scopeLevel", "site"),
        "siteId": (data.get("siteIds") or [""])[0],
        "accountId": (data.get("accountIds") or [""])[0],
        "generatedAlerts": 0,
        "lastAlertTime": None,
    }
    store.save("star_rules", rule_id, rule)
    return {"data": rule}


def set_incident_status(status: str, ids: list[str], actor_user_id: str | None = None) -> dict:
    """Set the incident status on a list of alerts.

    Implements POST /cloud-detection/alerts/incident.

    Args:
        status: Status string (e.g. ``"IN_PROGRESS"``).
        ids: List of alert IDs to update.
        actor_user_id: ID of the acting user, if authenticated.

    Returns:
        Dict with ``data.affected`` indicating how many alerts were updated.
    """
    affected = 0
    for alert_id in ids:
        alert = alert_repo.get(alert_id)
        if not alert:
            continue
        alert.alertInfo["incidentStatus"] = status
        alert.alertInfo["updatedAt"] = utc_now()
        alert_repo.save(alert)
        webhook_commands.fire_event(ALERT_UPDATED, record_dict(alert))
        affected += 1
    return {"data": {"affected": affected}}


class UnfilterableError(ValueError):
    """A delete filter this install cannot answer, refused rather than guessed."""


#: Delete-filter member -> the filter the rule list already answers. The
#: delete body names them in the plural where the list route takes the
#: singular, and the rest carry the same names on both.
_RULE_FILTER_ALIASES = {
    "statuses": "status",
    "severities": "severity",
    "queryTypes": "queryType",
    "s1qlSubstring": "s1ql__contains",
    "descriptionSubstring": "description__contains",
}

#: Members the rule list answers under their own name.
_RULE_FILTER_DIRECT = (
    "name__contains", "description__contains", "expirationMode", "expired",
    "scopeId", "siteIds", "accountIds", "s1ql__contains",
)


def delete_star_rules(filter_obj: dict) -> dict:
    """Delete the STAR rules a filter selects, and report how many.

    The 2.1 API deletes rules by filter — there is no ids member and no
    per-rule path — so a caller says which rules by describing them. Two
    things this route will not do: delete on an empty filter, which
    describes every rule the install has, and delete on a filter whose only
    members this install cannot answer, which would delete a different set
    than the one asked for. Both are refused.

    Args:
        filter_obj: The body's ``filter`` object.

    Returns:
        ``{"data": {"affected": n}}``.

    Raises:
        UnfilterableError: The filter is empty, or names nothing answerable.
    """
    from application.alerts.queries import filter_star_rules  # noqa: PLC0415
    from repository.store import store  # noqa: PLC0415 - avoids an import cycle

    params = _rule_filter_params(filter_obj)
    matched = filter_star_rules(params)
    for rule in matched:
        store.delete("star_rules", str(rule["id"]))
    return {"data": {"affected": len(matched)}}


def _rule_filter_params(filter_obj: dict) -> dict:
    """A delete filter as the parameters the rule list already understands."""
    if not filter_obj:
        msg = "filter is required"
        raise UnfilterableError(msg)

    params: dict = {}
    for name, value in filter_obj.items():
        target = _RULE_FILTER_ALIASES.get(name, name if name in _RULE_FILTER_DIRECT else None)
        if target is None or value in (None, "", [], {}):
            continue
        params[target] = (
            ",".join(str(item) for item in value) if isinstance(value, list) else str(value)
        )
    if not params:
        named = ", ".join(sorted(filter_obj))
        msg = f"this install cannot select rules by {named}"
        raise UnfilterableError(msg)
    return params
