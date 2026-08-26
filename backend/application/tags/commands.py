"""Write commands for scoped tag definitions (tag-manager CRUD)."""

from repository.account_repo import account_repo
from repository.agent_repo import agent_repo
from repository.group_repo import group_repo
from repository.site_repo import site_repo
from repository.tag_repo import tag_repo
from utils.dt import utc_now
from utils.id_gen import new_id
from utils.serde import record_dict


class InvalidTagError(ValueError):
    """A tag the 2.1 API would refuse to create."""


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

    The 2.1 swagger requires `key`, `value` and `type` inside `data`. A body
    that carries none of them used to create a tag with an empty key and an
    empty value and answer 200 with it — a tag nothing can be found by, and
    a client that sent its fields flat rather than under `data` had no way
    to tell.

    Args:
        body: Request body with ``data`` and ``filter`` keys.
        user_name: Display name of the creating user.
        user_id: ID of the creating user.

    Returns:
        Single-item response envelope.

    Raises:
        InvalidTagError: A required member is missing.
    """
    data = body.get("data") or {}
    missing = [name for name in ("key", "value", "type") if not str(data.get(name) or "").strip()]
    if missing:
        msg = f"data.{missing[0]} is required"
        raise InvalidTagError(msg)
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
    return {"data": record_dict(tag)}


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

    return {"data": record_dict(tag)}


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


class UnfilterableError(ValueError):
    """A delete filter this install cannot answer, refused rather than guessed."""


def delete_tags(filter_obj: dict) -> dict:
    """Delete the tag definitions a filter selects, and report how many.

    The 2.1 API deletes tags by filter rather than by path. `tagIds` names
    them outright; `query` is the free-text search the UI sends, over key,
    value and description; a scope member selects the tags defined at that
    scope. An empty filter selects every tag this install has, which the
    route refuses rather than acts on.

    Args:
        filter_obj: The body's ``filter`` object.

    Returns:
        ``{"data": {"affected": n}}``.

    Raises:
        UnfilterableError: The filter is empty, or names nothing answerable.
    """
    if not filter_obj:
        msg = "filter is required"
        raise UnfilterableError(msg)

    tag_ids = filter_obj.get("tagIds") or []
    if isinstance(tag_ids, str):
        tag_ids = [t for t in tag_ids.split(",") if t]
    excluded = set(filter_obj.get("tagIdsExcluded") or [])
    query = str(filter_obj.get("query") or "").lower()
    scope_level, scope_id, _ = _resolve_scope(filter_obj)
    scoped = any(
        filter_obj.get(name) for name in ("tenant", "groupIds", "siteIds", "accountIds")
    )

    if not tag_ids and not query and not scoped:
        named = ", ".join(sorted(filter_obj))
        msg = f"this install cannot select tags by {named}"
        raise UnfilterableError(msg)

    affected = 0
    for tag in list(tag_repo.list_all()):
        if tag.id in excluded:
            continue
        if tag_ids and tag.id not in tag_ids:
            continue
        if query and query not in " ".join(
            str(part or "").lower() for part in (tag.key, tag.value, tag.description)
        ):
            continue
        if scoped and not tag_ids and (tag.scopeLevel, tag.scopeId) != (scope_level, scope_id):
            continue
        affected += int(delete_tag(tag.id)["data"]["affected"])
    return {"data": {"affected": affected}}
