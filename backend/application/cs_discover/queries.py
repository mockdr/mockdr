"""CrowdStrike Falcon Discover application query handlers.

Provides a Discover-format view of the canonical ``installed_apps`` store,
mapping S1 agent IDs to CS device IDs via the ``edr_id_map`` collection.
"""
from __future__ import annotations

import uuid

from repository.store import store
from utils.cs_fql import apply_fql


def _build_id_map() -> dict[str, str]:
    """Build a mapping from S1 agent_id → CS device_id."""
    return {
        agent_id: mapping["cs_device_id"]
        for agent_id, mapping in (
            (aid, store.get("edr_id_map", aid))
            for aid in [m["cs_device_id"] for m in store.get_all("edr_id_map")]
        )
        if mapping and "cs_device_id" in mapping
    }


def _build_agent_to_cs_map() -> dict[str, str]:
    """Build agent_id → cs_device_id mapping from edr_id_map store."""
    result: dict[str, str] = {}
    for item in store.get_all("edr_id_map"):
        if isinstance(item, dict) and "cs_device_id" in item:
            # The edr_id_map is keyed by agent_id, so we need to find the key
            # We iterate the collection which returns values; we need agent_ids
            pass
    # Use direct store access to get all mappings with their keys
    all_maps = store._collections["edr_id_map"]  # noqa: SLF001
    for agent_id, mapping in all_maps.items():
        if isinstance(mapping, dict) and "cs_device_id" in mapping:
            result[agent_id] = mapping["cs_device_id"]
    return result


def _transform_app_to_discover(app: dict, cs_device_id: str) -> dict:
    """Transform a canonical installed_app record to CS Discover format."""
    return {
        "id": app.get("id", ""),
        "name": app.get("name", ""),
        "version": app.get("version", ""),
        "vendor": app.get("publisher", app.get("publisherName", "")),
        "category": app.get("type", "application"),
        "installation_timestamp": app.get("installedDate", ""),
        "last_updated_timestamp": app.get("installedDate", ""),
        "host": {
            "aid": cs_device_id,
            "platform_name": _os_to_platform(app.get("osType", "")),
        },
        "aid": cs_device_id,
    }


def _os_to_platform(os_type: str) -> str:
    """Map S1 osType to CS platform_name."""
    return {"windows": "Windows", "macos": "Mac", "linux": "Linux"}.get(
        os_type.lower() if os_type else "", "Windows",
    )


def combined_applications(
    filter_fql: str | None,
    limit: int,
    offset: int,
    sort: str | None,
    after: str | None,
) -> dict:
    """Return installed applications in CrowdStrike Discover format.

    Maps canonical installed_apps → Discover application objects, translating
    S1 agent IDs to CS device IDs.

    Args:
        filter_fql: FQL filter string.
        limit: Page size (max 100).
        offset: Numeric offset (used when ``after`` is not provided).
        sort: Sort expression (e.g. ``"name.asc"``).
        after: Cursor for next page (stringified index).

    Returns:
        CrowdStrike combined response with Discover application resources.
    """
    agent_to_cs = _build_agent_to_cs_map()

    # Get all installed apps from canonical store
    all_apps = store.get_all("installed_apps")

    # Also enrich each app with OS type from the agent
    from repository.agent_repo import agent_repo
    agent_os_map: dict[str, str] = {}
    for agent in agent_repo.list_all():
        agent_os_map[agent.id] = agent.osType

    # Transform to Discover format
    discover_apps: list[dict] = []
    for app in all_apps:
        agent_id = app.get("agentId", "")
        cs_device_id = agent_to_cs.get(agent_id)
        if not cs_device_id:
            continue
        d_app = _transform_app_to_discover(app, cs_device_id)
        # Set OS from agent
        os_type = agent_os_map.get(agent_id, "")
        d_app["host"]["platform_name"] = _os_to_platform(os_type)
        discover_apps.append(d_app)

    # Apply FQL filter if provided
    if filter_fql:
        discover_apps = apply_fql(discover_apps, filter_fql)

    # Sort
    if sort:
        parts = sort.rsplit(".", 1)
        field_name = parts[0]
        desc = len(parts) > 1 and parts[1].lower() == "desc"
        discover_apps.sort(
            key=lambda r: str(r.get(field_name, "")), reverse=desc,
        )
    else:
        discover_apps.sort(key=lambda r: str(r.get("name", "")))

    total = len(discover_apps)

    # Cursor-based pagination (via ``after``)
    start = int(after) if after else offset
    page = discover_apps[start : start + limit]
    next_after = str(start + limit) if start + limit < total else ""

    return {
        "meta": {
            "query_time": 0.01,
            "powered_by": "discover-api",
            "trace_id": str(uuid.uuid4()),
            "pagination": {
                "after": next_after,
                "limit": limit,
                "total": total if start == 0 else 0,
            },
        },
        "resources": page,
        "errors": [],
    }
