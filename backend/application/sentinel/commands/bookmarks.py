"""Sentinel bookmark command handlers."""
from __future__ import annotations

import uuid

from domain.sentinel.bookmark import SentinelBookmark
from repository.sentinel.bookmark_repo import sentinel_bookmark_repo
from utils.dt import utc_now


def create_or_update_bookmark(bookmark_id: str, properties: dict) -> SentinelBookmark:
    """Create or update an investigation bookmark.

    Args:
        bookmark_id: Bookmark resource name.
        properties:  ARM properties bag.

    Returns:
        The created/updated bookmark.
    """
    now = utc_now()
    existing = sentinel_bookmark_repo.get(bookmark_id)

    if existing:
        for key in ("displayName", "notes", "query", "queryResult", "labels"):
            if key in properties:
                snake = {"displayName": "display_name", "queryResult": "query_result"}.get(key, key)
                setattr(existing, snake, properties[key])
        existing.updated = now
        existing.etag = uuid.uuid4().hex[:8]
        sentinel_bookmark_repo.save(existing)
        return existing

    bm = SentinelBookmark(
        bookmark_id=bookmark_id,
        display_name=properties.get("displayName", ""),
        notes=properties.get("notes", ""),
        query=properties.get("query", ""),
        query_result=properties.get("queryResult", ""),
        incident_id=properties.get("incidentId", ""),
        labels=properties.get("labels", []),
        created=now,
        updated=now,
        etag=uuid.uuid4().hex[:8],
    )
    sentinel_bookmark_repo.save(bm)
    return bm


def delete_bookmark(bookmark_id: str) -> bool:
    """Delete a bookmark."""
    return sentinel_bookmark_repo.delete(bookmark_id)
