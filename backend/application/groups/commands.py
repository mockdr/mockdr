"""Write-side command handlers for Group CRUD.

DELETE /groups/{id}             → delete_group
POST   /groups                  → create_group
PUT    /groups/{id}             → update_group
PUT    /groups/{id}/move-agents → move_agents_to_group
"""
import uuid
from dataclasses import asdict

from domain.group import Group
from repository.group_repo import group_repo
from repository.site_repo import site_repo
from utils.dt import utc_now
from utils.id_gen import new_id
from utils.internal_fields import GROUP_INTERNAL_FIELDS
from utils.strip import strip_fields


def create_group(data: dict) -> dict:
    """Create a new group within a site.

    Args:
        data: Inner data dict from the S1-style ``{"data": {...}}`` request body.
              Required: name, siteId, type.
              Optional: description, filterId, inherits.

    Returns:
        Dict with ``data`` containing the created group record (internal fields stripped).
    """
    now = utc_now()
    site_id: str = data.get("siteId", "")
    site = site_repo.get(site_id)
    site_name: str = site.name if site else ""
    account_id: str = site.accountId if site else ""
    account_name: str = site.accountName if site else ""

    group = Group(
        id=new_id(),
        name=data.get("name", ""),
        siteId=site_id,
        type=data.get("type", "static"),
        createdAt=now,
        updatedAt=now,
        totalAgents=0,
        isDefault=False,
        rank=None,
        inherits=bool(data.get("inherits", True)),
        description=data.get("description"),
        filterId=data.get("filterId"),
        filterName=None,
        registrationToken=str(uuid.uuid4()),
        creator=None,
        creatorId=None,
        # Internal fields
        siteName=site_name,
        accountId=account_id,
        accountName=account_name,
    )
    group_repo.save(group)
    return {"data": strip_fields(asdict(group), GROUP_INTERNAL_FIELDS)}


def delete_group(group_id: str) -> dict | None:
    """Delete a group by ID.

    Refuses to delete the default group.

    Args:
        group_id: The group's unique identifier.

    Returns:
        Dict with ``data.success`` True on success,
        ``{"error": "default"}`` if the group is the default group,
        or None if not found.
    """
    group = group_repo.get(group_id)
    if not group:
        return None
    if group.isDefault:
        return {"error": "default"}

    # Reassign agents in this group to the default group in the same site
    from repository.agent_repo import agent_repo

    site_groups = group_repo.get_by_site(group.siteId) if group.siteId else []
    fallback_group = next(
        (g for g in site_groups if g.isDefault and g.id != group_id),
        next((g for g in site_groups if g.id != group_id), None),
    )
    for agent in agent_repo.list_all():
        if agent.groupId == group_id:
            if fallback_group:
                agent.groupId = fallback_group.id
                agent.groupName = fallback_group.name
            else:
                agent.groupId = ""
                agent.groupName = ""
            agent_repo.save(agent)

    group_repo.delete(group_id)
    return {"data": {"success": True}}


def move_agents_to_group(group_id: str, agent_ids: list[str]) -> dict:
    """Move a list of agents into the target group.

    Args:
        group_id: ID of the destination group.
        agent_ids: IDs of agents to reassign.

    Returns:
        Dict with ``data.affected`` count of successfully moved agents, or
        ``{"error": "not_found"}`` if the target group does not exist.
    """
    from repository.agent_repo import agent_repo  # local import avoids circular dep

    target_group = group_repo.get(group_id)
    if not target_group:
        return {"error": "not_found"}

    affected = 0
    for aid in agent_ids:
        agent = agent_repo.get(aid)
        if not agent:
            continue
        agent.groupId = target_group.id
        agent.groupName = target_group.name
        agent_repo.save(agent)
        affected += 1
    return {"data": {"affected": affected}}


def update_group(group_id: str, data: dict) -> dict | None:
    """Apply a partial update to an existing group.

    Args:
        group_id: The group's unique identifier.
        data: Inner data dict from the S1-style ``{"data": {...}}`` request body.
              All fields optional; only present keys are overwritten.

    Returns:
        Dict with ``data`` containing the updated group, or None if not found.
    """
    group = group_repo.get(group_id)
    if not group:
        return None

    updatable = ("name", "description", "type", "inherits", "filterId")
    for field in updatable:
        if field in data:
            setattr(group, field, data[field])
    group.updatedAt = utc_now()
    group_repo.save(group)
    return {"data": strip_fields(asdict(group), GROUP_INTERNAL_FIELDS)}
