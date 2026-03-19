"""Write commands for scoped tag definitions (tag-manager CRUD)."""
from dataclasses import asdict

from repository.account_repo import account_repo
from repository.agent_repo import agent_repo
from repository.group_repo import group_repo
from repository.site_repo import site_repo
from repository.tag_repo import tag_repo
from utils.dt import utc_now
from utils.id_gen import new_id


def _resolve_scope(filter_obj: dict) -> tuple[str, str, str]:
    """Determine scope level, scope ID, and scope path from the filter object.

    Returns:
        (scopeLevel, scopeId, scopePath)
    """
    if filter_obj.get("tenant"):
        return "global", "", "Global"

    group_ids = filter_obj.get("groupIds", [])
    if group_ids:
        gid = group_ids[0] if isinstance(group_ids, list) else str(group_ids).split(",")[0]
        group = group_repo.get(gid)
        if group:
            site = site_repo.get(group.siteId)
            account_name = group.accountName or "Global"
            site_name = group.siteName or (site.name if site else "")
            path = f"Global\\{account_name}\\{site_name}\\{group.name}"
            return "group", gid, path
        return "group", gid, "Global"

    site_ids = filter_obj.get("siteIds", [])
    if site_ids:
        sid = site_ids[0] if isinstance(site_ids, list) else str(site_ids).split(",")[0]
        site = site_repo.get(sid)
        if site:
            path = f"Global\\{site.accountName}\\{site.name}"
            return "site", sid, path
        return "site", sid, "Global"

    account_ids = filter_obj.get("accountIds", [])
    if account_ids:
        aid = account_ids[0] if isinstance(account_ids, list) else str(account_ids).split(",")[0]
        account = account_repo.get(aid)
        if account:
            return "account", aid, f"Global\\{account.name}"
        return "account", aid, "Global"

    return "global", "", "Global"


def create_tag(body: dict, user_name: str = "", user_id: str = "") -> dict:
    """Create a new tag definition.

    Args:
        body: Request body with ``data`` and ``filter`` keys.
        user_name: Display name of the creating user.
        user_id: ID of the creating user.

    Returns:
        Single-item response envelope.
    """
    data = body.get("data", {})
    filter_obj = body.get("filter", {})
    scope_level, scope_id, scope_path = _resolve_scope(filter_obj)

    now = utc_now()
    from domain.tag import Tag

    tag = Tag(
        id=new_id(),
        key=data.get("key", ""),
        value=data.get("value", ""),
        type=data.get("type", "agents"),
        description=data.get("description", ""),
        scopeId=scope_id,
        scopeLevel=scope_level,
        scopePath=scope_path,
        createdAt=now,
        updatedAt=now,
        createdBy=user_name,
        updatedBy=user_name,
        createdById=user_id,
        updatedById=user_id,
    )
    tag_repo.save(tag)
    return {"data": asdict(tag)}


def update_tag(tag_id: str, body: dict, user_name: str = "", user_id: str = "") -> dict | None:
    """Update a tag definition's key, value, or description.

    Returns:
        Updated tag response, or None if not found.
    """
    tag = tag_repo.get(tag_id)
    if not tag:
        return None

    data = body.get("data", body)
    if "key" in data:
        tag.key = data["key"]
    if "value" in data:
        tag.value = data["value"]
    if "description" in data:
        tag.description = data["description"]

    tag.updatedAt = utc_now()
    tag.updatedBy = user_name
    tag.updatedById = user_id
    tag_repo.save(tag)

    # Update key/value on all agent assignments referencing this tag
    for agent in agent_repo.list_all():
        s1_tags = (agent.tags or {}).get("sentinelone", [])
        changed = False
        for entry in s1_tags:
            if entry.get("id") == tag_id:
                entry["key"] = tag.key
                entry["value"] = tag.value
                changed = True
        if changed:
            updated = dict(agent.tags) if agent.tags else {}
            updated["sentinelone"] = s1_tags
            agent.tags = updated
            agent_repo.save(agent)

    return {"data": asdict(tag)}


def delete_tag(tag_id: str) -> dict:
    """Delete a tag definition and remove all agent assignments.

    Returns:
        Action response with affected count.
    """
    deleted = tag_repo.delete(tag_id)

    # Remove from all agents
    for agent in agent_repo.list_all():
        s1_tags = (agent.tags or {}).get("sentinelone", [])
        before = len(s1_tags)
        s1_tags = [t for t in s1_tags if t.get("id") != tag_id]
        if len(s1_tags) != before:
            updated = dict(agent.tags) if agent.tags else {}
            updated["sentinelone"] = s1_tags
            agent.tags = updated

    return {"data": {"affected": 1 if deleted else 0}}
