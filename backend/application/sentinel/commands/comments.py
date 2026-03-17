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
) -> SentinelIncidentComment:
    """Create or update an incident comment.

    Args:
        incident_id: Parent incident ID.
        comment_id:  Comment resource name.
        message:     Comment text.

    Returns:
        The created/updated comment.
    """
    existing = sentinel_incident_comment_repo.get(comment_id)
    now = utc_now()

    if existing:
        existing.message = message
        existing.etag = uuid.uuid4().hex[:8]
        sentinel_incident_comment_repo.save(existing)
        return existing

    comment = SentinelIncidentComment(
        comment_id=comment_id,
        incident_id=incident_id,
        message=message,
        created_time_utc=now,
        etag=uuid.uuid4().hex[:8],
    )
    sentinel_incident_comment_repo.save(comment)
    return comment


def delete_comment(comment_id: str) -> bool:
    """Delete an incident comment."""
    return sentinel_incident_comment_repo.delete(comment_id)
