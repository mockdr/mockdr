"""CrowdStrike Falcon Host command handlers (mutations)."""
from __future__ import annotations

from dataclasses import asdict

from repository.cs_host_repo import cs_host_repo
from utils.cs_response import build_cs_action_response
from utils.dt import utc_now


def contain_host(ids: list[str]) -> dict:
    """Network-contain one or more hosts.

    Sets ``status`` to ``"containment_pending"`` for each matched host.

    Args:
        ids: List of device IDs to contain.

    Returns:
        CS action response with affected host resources.
    """
    affected: list[dict] = []
    for device_id in ids:
        host = cs_host_repo.get(device_id)
        if not host:
            continue
        host.status = "containment_pending"
        host.modified_timestamp = utc_now()
        cs_host_repo.save(host)
        affected.append({"id": host.device_id})
    return build_cs_action_response(affected)


def lift_containment(ids: list[str]) -> dict:
    """Lift network containment from one or more hosts.

    Sets ``status`` back to ``"normal"`` for each matched host.

    Args:
        ids: List of device IDs to lift containment from.

    Returns:
        CS action response with affected host resources.
    """
    affected: list[dict] = []
    for device_id in ids:
        host = cs_host_repo.get(device_id)
        if not host:
            continue
        host.status = "normal"
        host.modified_timestamp = utc_now()
        cs_host_repo.save(host)
        affected.append({"id": host.device_id})
    return build_cs_action_response(affected)


def hide_host(ids: list[str]) -> dict:
    """Hide (soft-delete) hosts.

    Removes the host from the repository entirely, matching real CS behavior.

    Args:
        ids: List of device IDs to hide.

    Returns:
        CS action response with affected host resources.
    """
    affected: list[dict] = []
    for device_id in ids:
        if cs_host_repo.delete(device_id):
            affected.append({"id": device_id})
    return build_cs_action_response(affected)


def tag_hosts(ids: list[str], tags: list[str], action: str) -> dict:
    """Add or remove FalconGroupingTags from hosts.

    Args:
        ids:    List of device IDs to update.
        tags:   List of tag strings to add or remove.
        action: ``"add"`` to append tags, ``"remove"`` to strip them.

    Returns:
        CS action response with updated host resources.
    """
    affected: list[dict] = []
    for device_id in ids:
        host = cs_host_repo.get(device_id)
        if not host:
            continue
        current_tags = list(host.tags)
        if action == "add":
            for tag in tags:
                if tag not in current_tags:
                    current_tags.append(tag)
        elif action == "remove":
            tag_set = set(tags)
            current_tags = [t for t in current_tags if t not in tag_set]
        host.tags = current_tags
        host.modified_timestamp = utc_now()
        cs_host_repo.save(host)
        affected.append(asdict(host))
    return build_cs_action_response(affected)
