"""Sentinel watchlist command handlers."""
from __future__ import annotations

import uuid
from typing import Any, cast

from domain.sentinel.watchlist import SentinelWatchlist
from repository.sentinel.watchlist_repo import sentinel_watchlist_repo
from utils.dt import utc_now


def create_or_update_watchlist(alias: str, properties: dict) -> SentinelWatchlist:
    """Create or update a watchlist.

    Args:
        alias:      Watchlist alias (resource name).
        properties: ARM properties bag.

    Returns:
        The created/updated watchlist.
    """
    now = utc_now()
    existing = sentinel_watchlist_repo.get(alias)

    if existing:
        if "displayName" in properties:
            existing.display_name = properties["displayName"]
        if "description" in properties:
            existing.description = properties["description"]
        if "itemsSearchKey" in properties:
            existing.items_search_key = properties["itemsSearchKey"]
        existing.updated = now
        existing.etag = uuid.uuid4().hex[:8]
        sentinel_watchlist_repo.save(existing)
        return existing

    wl = SentinelWatchlist(
        watchlist_alias=alias,
        display_name=properties.get("displayName", alias),
        description=properties.get("description", ""),
        items_search_key=properties.get("itemsSearchKey", ""),
        provider=properties.get("provider", "Microsoft"),
        source=properties.get("source", "Local file"),
        created=now,
        updated=now,
        etag=uuid.uuid4().hex[:8],
    )
    sentinel_watchlist_repo.save(wl)
    return wl


def delete_watchlist(alias: str) -> bool:
    """Delete a watchlist."""
    return sentinel_watchlist_repo.delete(alias)


def create_or_update_watchlist_item(
    alias: str,
    item_id: str,
    properties: dict,
) -> dict | None:
    """Create or update a watchlist item.

    Args:
        alias:      Watchlist alias.
        item_id:    Item resource name.
        properties: Item properties (itemsKeyValue + arbitrary fields).

    Returns:
        The item dict, or None if watchlist not found.
    """
    wl = sentinel_watchlist_repo.get(alias)
    if not wl:
        return None

    item_data = properties.get("itemsKeyValue", properties)
    if isinstance(item_data, str):
        item_data = {"value": item_data}
    item_data["_key"] = item_id

    # Upsert
    for i, existing in enumerate(wl.items):
        if existing.get("_key") == item_id:
            wl.items[i] = cast(dict[str, object], item_data)
            sentinel_watchlist_repo.save(wl)
            return cast(dict[str, Any], item_data)

    wl.items.append(cast(dict[str, object], item_data))
    sentinel_watchlist_repo.save(wl)
    return cast(dict[str, Any], item_data)


def delete_watchlist_item(alias: str, item_id: str) -> bool:
    """Delete a watchlist item."""
    wl = sentinel_watchlist_repo.get(alias)
    if not wl:
        return False
    original = len(wl.items)
    wl.items = [it for it in wl.items if it.get("_key") != item_id]
    if len(wl.items) < original:
        sentinel_watchlist_repo.save(wl)
        return True
    return False
