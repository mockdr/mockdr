from dataclasses import asdict

from application.webhooks import commands as webhook_commands
from domain.webhook import ALERT_UPDATED
from repository.alert_repo import alert_repo
from repository.store import store
from utils.dt import utc_now
from utils.id_gen import new_id


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
        webhook_commands.fire_event(ALERT_UPDATED, asdict(alert))
        affected += 1
    return {"data": {"affected": affected}}


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
        "createdAt": now,
        "updatedAt": now,
        "creator": user_id or "",
        "creatorId": user_id or "",
    }
    store.save("star_rules", rule_id, rule)
    return {"data": rule}


def list_star_rules() -> dict:
    """List all STAR custom detection rules.

    Implements GET /cloud-detection/rules.

    Returns:
        Dict with ``data`` containing all rules.
    """
    rules = store.get_all("star_rules")
    return {"data": rules}


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
        webhook_commands.fire_event(ALERT_UPDATED, asdict(alert))
        affected += 1
    return {"data": {"affected": affected}}
