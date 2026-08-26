"""Sentinel incident comment command handlers."""
from __future__ import annotations

import uuid

from domain.sentinel.incident_comment import SentinelIncidentComment
from repository.sentinel.incident_comment_repo import sentinel_incident_comment_repo
from utils.dt import utc_now


def create_or_update_comment(
    incident_id: str,
    comment_id: str,
    message: str,
    author: str = "",
) -> SentinelIncidentComment:
    """Create or update an incident comment.

    Args:
        incident_id: Parent incident ID.
        comment_id:  Comment resource name.
        message:     Comment text.
        author:      The client that made the comment — the application the
                     token was issued to, which is what Sentinel records for
                     an app-only caller.

    Returns:
        The created/updated comment.
    """
    existing = sentinel_incident_comment_repo.get(comment_id)
    now = utc_now()

    if existing:
        existing.message = message
        existing.last_modified_time_utc = now
        existing.etag = uuid.uuid4().hex[:8]
        sentinel_incident_comment_repo.save(existing)
        return existing

    comment = SentinelIncidentComment(
        comment_id=comment_id,
        incident_id=incident_id,
        message=message,
        author_name=author,
        author_object_id=author,
        created_time_utc=now,
        last_modified_time_utc=now,
        etag=uuid.uuid4().hex[:8],
    )
    sentinel_incident_comment_repo.save(comment)
    return comment


def delete_comment(comment_id: str) -> bool:
    """Delete an incident comment."""
    return sentinel_incident_comment_repo.delete(comment_id)
