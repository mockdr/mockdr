from dataclasses import asdict

from domain.firewall_rule import FirewallRule
from repository.activity_repo import activity_repo
from repository.firewall_repo import firewall_repo
from utils.dt import utc_now
from utils.id_gen import new_id
from utils.internal_fields import FIREWALL_INTERNAL_FIELDS
from utils.strip import strip_fields


def create_rule(data: dict) -> dict:
    """Create a new firewall rule and persist it."""
    now = utc_now()
    rule = FirewallRule(
        id=new_id(),
        name=data.get("name", ""),
        description=data.get("description", ""),
        status=data.get("status", "Enabled"),
        action=data.get("action", "Allow"),
        direction=data.get("direction", "any"),
        order=data.get("order", 0),
        osType=data.get("osType", "windows"),
        osTypes=data.get("osTypes", ["windows"]),
        protocol=data.get("protocol"),
        ruleCategory=data.get("ruleCategory", "firewall"),
        scope=data.get("scope", "global"),
        scopeId=data.get("scopeId"),
        editable=True,
        tag=data.get("tag", ""),
        creator=data.get("creator"),
        creatorId=data.get("creatorId"),
        localPort=data.get("localPort", {"type": "any", "values": []}),
        remotePort=data.get("remotePort", {"type": "any", "values": []}),
        localHost=data.get("localHost", {"type": "any", "values": []}),
        remoteHost=data.get("remoteHost", {"type": "any", "values": []}),
        remoteHosts=data.get("remoteHosts", [{"type": "any", "values": []}]),
        application=data.get("application", {"type": "any", "values": []}),
        location=data.get("location", {"type": "all", "values": []}),
        siteId=data.get("siteId", ""),
        createdAt=now,
        updatedAt=now,
    )
    firewall_repo.save(rule)
    activity_repo.create(
        activity_type=300,
        description=f"Firewall rule created: {rule.name}",
        site_id=rule.siteId,
    )
    return {"data": strip_fields(asdict(rule), FIREWALL_INTERNAL_FIELDS)}


def update_rule(rule_id: str, data: dict) -> dict | None:
    """Update an existing firewall rule. Returns None if not found."""
    rule = firewall_repo.get(rule_id)
    if rule is None:
        return None
    record = asdict(rule)
    updatable = {
        "name", "description", "status", "action", "direction", "order",
        "osType", "osTypes", "protocol", "scope", "scopeId", "tag",
        "localPort", "remotePort", "localHost", "remoteHost", "remoteHosts",
        "application", "location",
    }
    for key, value in data.items():
        if key in updatable:
            record[key] = value
    record["updatedAt"] = utc_now()
    updated = FirewallRule(**record)
    firewall_repo.save(updated)
    activity_repo.create(
        activity_type=301,
        description=f"Firewall rule updated: {updated.name}",
        site_id=updated.siteId,
    )
    return {"data": strip_fields(asdict(updated), FIREWALL_INTERNAL_FIELDS)}


def delete_rule(rule_id: str) -> dict | None:
    """Delete a firewall rule by ID. Returns None if not found."""
    rule = firewall_repo.get(rule_id)
    if not rule:
        return None
    firewall_repo.delete(rule_id)
    activity_repo.create(
        activity_type=302,
        description=f"Firewall rule deleted: {rule.name}",
        site_id=rule.siteId,
    )
    return {"data": {"success": True}}
