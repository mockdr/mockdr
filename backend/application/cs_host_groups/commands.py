"""CrowdStrike Falcon Host Group command handlers (mutations)."""
from __future__ import annotations

import uuid as _uuid

from domain.cs_host_group import CsHostGroup
from repository.cs_host_group_repo import cs_host_group_repo
from repository.cs_host_repo import cs_host_repo
from utils.cs_response import build_cs_action_response, build_cs_entity_response
from utils.dt import utc_now
from utils.serde import record_dict


def create_host_groups(resources: list[dict]) -> dict:
    """Create every group in ``resources``.

    ``HostGroupsCreateGroupsReqV1`` is a *collection*: one call creates as
    many groups as it carries, and the answer lists them all. Reading the
    body one level flatter than that is not a shape quibble — a client
    sending the documented body got a group named ``""``.

    Args:
        resources: The ``resources`` members, each ``{name, group_type,
              description?, assignment_rule?}``.

    Returns:
        CS entity response containing every newly created host group.
    """
    created = []
    for body in resources:
        now = utc_now()
        group = CsHostGroup(
            id=str(_uuid.uuid4()),
            name=body.get("name", ""),
            description=body.get("description", ""),
            group_type=body.get("group_type", "static"),
            assignment_rule=body.get("assignment_rule", ""),
            created_by=body.get("created_by", "api-client"),
            created_timestamp=now,
            modified_by=body.get("modified_by", "api-client"),
            modified_timestamp=now,
        )
        cs_host_group_repo.save(group)
        created.append(record_dict(group))
    return build_cs_entity_response(created)


def update_host_groups(resources: list[dict]) -> dict:
    """Update every group named in ``resources``.

    ``id`` identifies each group; only the members present are overwritten.
    A group that does not exist is skipped, which is how Falcon answers a
    partially resolvable list — the resources it did update, and no error.

    Args:
        resources: The ``resources`` members, each ``{id, name?,
              description?, assignment_rule?}``.

    Returns:
        CS entity response with every group that was updated.
    """
    updated = []
    for body in resources:
        group = cs_host_group_repo.get(body.get("id", ""))
        if not group:
            continue
        for field_name in ("name", "description", "assignment_rule"):
            if field_name in body:
                setattr(group, field_name, body[field_name])
        group.modified_by = body.get("modified_by", "api-client")
        group.modified_timestamp = utc_now()
        cs_host_group_repo.save(group)
        updated.append(record_dict(group))
    return build_cs_entity_response(updated)


def delete_host_groups(ids: list[str]) -> dict:
    """Delete host groups by ID list.

    Also removes the group ID from the ``groups`` list on any hosts that
    were members of the deleted groups.

    Args:
        ids: List of host group IDs to delete.

    Returns:
        CS action response with affected group IDs.
    """
    affected: list[dict] = []
    for group_id in ids:
        if cs_host_group_repo.delete(group_id):
            affected.append({"id": group_id})
            # Clean up host membership references.
            for host in cs_host_repo.list_all():
                if group_id in host.groups:
                    host.groups = [g for g in host.groups if g != group_id]
                    cs_host_repo.save(host)
    return build_cs_action_response(affected)


def manage_group_members(
    host_group_id: str,
    action: str,
    host_ids: list[str],
) -> dict:
    """Add or remove hosts from a group.

    Args:
        host_group_id: ID of the host group to modify.
        action:        ``"add-hosts"`` or ``"remove-hosts"``.
        host_ids:      List of device IDs to add or remove.

    Returns:
        CS action response with affected host resources.
    """
    affected: list[dict] = []
    for device_id in host_ids:
        host = cs_host_repo.get(device_id)
        if not host:
            continue
        if action == "add-hosts":
            if host_group_id not in host.groups:
                host.groups.append(host_group_id)
        elif action == "remove-hosts":
            host.groups = [g for g in host.groups if g != host_group_id]
        host.modified_timestamp = utc_now()
        cs_host_repo.save(host)
        affected.append({"id": device_id})
    return build_cs_action_response(affected)
