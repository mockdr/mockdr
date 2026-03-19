"""Sentinel watchlist query handlers (read-only)."""
from __future__ import annotations

from repository.sentinel.watchlist_repo import sentinel_watchlist_repo
from utils.sentinel.response import build_arm_list, build_arm_resource


def list_watchlists() -> dict:
    """Return all watchlists in ARM format."""
    items = []
    for wl in sentinel_watchlist_repo.list_all():
        items.append(build_arm_resource("watchlists", wl.watchlist_alias, {
            "displayName": wl.display_name,
            "description": wl.description,
            "provider": wl.provider,
            "source": wl.source,
            "itemsSearchKey": wl.items_search_key,
            "contentType": wl.content_type,
            "created": wl.created,
            "updated": wl.updated,
            "numberOfLinesToSkip": 0,
            "watchlistItemsCount": len(wl.items),
        }, etag=wl.etag))
    return build_arm_list(items)


def get_watchlist(alias: str) -> dict | None:
    """Return a single watchlist in ARM format."""
    wl = sentinel_watchlist_repo.get(alias)
    if not wl:
        return None
    return build_arm_resource("watchlists", wl.watchlist_alias, {
        "displayName": wl.display_name,
        "description": wl.description,
        "provider": wl.provider,
        "source": wl.source,
        "itemsSearchKey": wl.items_search_key,
        "contentType": wl.content_type,
        "created": wl.created,
        "updated": wl.updated,
        "watchlistItemsCount": len(wl.items),
    }, etag=wl.etag)


def list_watchlist_items(alias: str) -> dict | None:
    """Return all items for a watchlist."""
    wl = sentinel_watchlist_repo.get(alias)
    if not wl:
        return None
    items = []
    for item in wl.items:
        key = str(item.get("_key", ""))
        items.append(build_arm_resource("watchlistItems", key, {
            "itemsKeyValue": {k: v for k, v in item.items() if k != "_key"},
        }, etag=wl.etag))
    return build_arm_list(items)


def get_watchlist_item(alias: str, item_id: str) -> dict | None:
    """Return a single watchlist item."""
    wl = sentinel_watchlist_repo.get(alias)
    if not wl:
        return None
    for item in wl.items:
        if item.get("_key") == item_id:
            return build_arm_resource("watchlistItems", item_id, {
                "itemsKeyValue": {k: v for k, v in item.items() if k != "_key"},
            })
    return None
