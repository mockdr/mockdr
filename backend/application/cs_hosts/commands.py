"""CrowdStrike Falcon Host command handlers (mutations)."""
from __future__ import annotations

from repository.cs_host_repo import cs_host_repo
from utils.cs_response import build_cs_action_response
from utils.dt import utc_now
from utils.internal_fields import CS_HOST_INTERNAL_FIELDS
from utils.serde import record_dict
from utils.strip import strip_fields


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

    Sets ``status`` to ``"lift_containment_pending"``, which settles to
    ``"normal"`` once the sensor has acknowledged — the same way containment
    settles, and the state the fleet is seeded with. Going straight to
    ``normal`` skipped a state a client can legitimately observe.

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
        host.status = "lift_containment_pending"
        host.modified_timestamp = utc_now()
        cs_host_repo.save(host)
        affected.append({"id": host.device_id})
    return build_cs_action_response(affected)


def hide_host(ids: list[str]) -> dict:
    """Hide hosts, which Falcon can undo.

    ``hide_host`` "will delete a host" and ``unhide_host`` "will restore a
    host" — Falcon's own words, and its ``devices-hidden`` route lists what
    is hidden. Dropping the record made hiding irreversible: a host hidden
    by mistake could never come back, and the listing had nothing to show.

    Args:
        ids: List of device IDs to hide.

    Returns:
        CS action response with affected host resources.
    """
    return _set_hidden(ids, hidden=True)


def unhide_host(ids: list[str]) -> dict:
    """Restore hosts that were hidden, so detections resume for them.

    Args:
        ids: List of device IDs to restore.

    Returns:
        CS action response with affected host resources.
    """
    return _set_hidden(ids, hidden=False)


def _set_hidden(ids: list[str], *, hidden: bool) -> dict:
    affected: list[dict] = []
    for device_id in ids:
        host = cs_host_repo.get(device_id)
        if not host:
            continue
        host.hidden = hidden
        host.modified_timestamp = utc_now()
        cs_host_repo.save(host)
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
        affected.append(strip_fields(record_dict(host), CS_HOST_INTERNAL_FIELDS))
    return build_cs_action_response(affected)
