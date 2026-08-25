"""Elastic Security Cases command handlers (mutations)."""
from __future__ import annotations

import base64
import binascii
import uuid

from domain.es_case import EsCase
from domain.es_case_comment import EsCaseComment
from repository.es_case_comment_repo import es_case_comment_repo
from repository.es_case_repo import es_case_repo
from utils.dt import utc_now
from utils.es_case_serde import KIBANA_USER, serialise_case
from utils.serde import record_dict


def create_case(data: dict) -> dict:
    """Create a new case.

    Args:
        data: Request body with title, description, tags, etc.

    Returns:
        The newly created case as a dict.
    """
    now = utc_now()
    case = EsCase(
        id=str(uuid.uuid4()),
        title=data.get("title", ""),
        description=data.get("description", ""),
        status=data.get("status", "open"),
        severity=data.get("severity", "low"),
        tags=data.get("tags", []),
        connector=data.get("connector", {
            "id": "none", "name": "none", "type": ".none", "fields": None,
        }),
        settings=data.get("settings", {"syncAlerts": True}),
        owner=data.get("owner", "securitySolution"),
        assignees=data.get("assignees", []),
        created_at=now,
        created_by=data.get("created_by", dict(KIBANA_USER)),
    )
    es_case_repo.save(case)
    return serialise_case(record_dict(case))


def _next_version(current: str) -> str:
    """Issue the next opaque version token for a case.

    Kibana's tokens are base64 of a two-element sequence; the exact contents
    are not part of the contract, only that the token changes on each write.
    """
    try:
        decoded = base64.b64decode(current).decode()
        sequence, _, primary = decoded.strip("[]").partition(",")
        nxt = f"[{int(sequence) + 1},{primary.strip() or 1}]"
    except (ValueError, UnicodeDecodeError, binascii.Error):
        nxt = "[1,1]"
    return base64.b64encode(nxt.encode()).decode()


def update_case(case_id: str, data: dict) -> dict | None:
    """Update an existing case.

    Args:
        case_id: The UUID of the case to update.
        data:    Fields to update (title, description, status, tags, etc.).

    Returns:
        Updated case dict, or None if not found.
    """
    case = es_case_repo.get(case_id)
    if not case:
        return None

    now = utc_now()
    updatable = ("title", "description", "status", "severity", "tags",
                 "connector", "settings", "assignees")
    for field in updatable:
        if field in data:
            setattr(case, field, data[field])

    case.updated_at = now
    case.updated_by = data.get("updated_by", dict(KIBANA_USER))
    # The version is an opaque optimistic-concurrency token; Kibana issues a
    # new one on every write, which is what makes a stale version a conflict.
    case.version = _next_version(case.version)

    if data.get("status") == "closed":
        case.closed_at = now
        case.closed_by = case.updated_by
    elif data.get("status") in ("open", "in-progress"):
        case.closed_at = None
        case.closed_by = None

    es_case_repo.save(case)
    return serialise_case(record_dict(case))


def delete_case(case_id: str) -> bool:
    """Delete a case and all its comments.

    Args:
        case_id: The UUID of the case to delete.

    Returns:
        True if the case existed and was deleted, False otherwise.
    """
    if not es_case_repo.exists(case_id):
        return False

    # Remove all comments belonging to this case.
    for comment in es_case_comment_repo.get_by_case_id(case_id):
        es_case_comment_repo.delete(comment.id)

    return es_case_repo.delete(case_id)


def add_comment(case_id: str, data: dict) -> dict | None:
    """Add a comment to a case.

    Args:
        case_id: The UUID of the case.
        data:    Request body with comment text and type.

    Returns:
        The case the comment was added to, or None if it does not exist.
    """
    case = es_case_repo.get(case_id)
    if not case:
        return None

    now = utc_now()
    comment = EsCaseComment(
        id=str(uuid.uuid4()),
        case_id=case_id,
        comment=data.get("comment", ""),
        type=data.get("type", "user"),
        created_at=now,
        created_by=data.get("created_by", dict(KIBANA_USER)),
    )
    es_case_comment_repo.save(comment)

    # Update case comment count and timestamp.
    # Commenting is a change to the case, and Kibana stamps it as one: the
    # case's own updated_at and updated_by move.
    case.total_comment = len(es_case_comment_repo.get_by_case_id(case_id))
    case.updated_at = now
    case.updated_by = data.get("created_by", dict(KIBANA_USER))
    es_case_repo.save(case)

    # Kibana answers a comment write with the *case*, comments and all — not
    # with the comment. A client that read the answer as a comment found an
    # object with a different shape and no case to update from it.
    from application.es_cases.queries import get_case
    return get_case(case_id)


def update_comment(case_id: str, comment_id: str, data: dict) -> dict | None:
    """Update a comment on a case.

    Args:
        case_id:    The UUID of the case.
        comment_id: The UUID of the comment to update.
        data:       Fields to update (comment text, etc.).

    Returns:
        Updated comment dict, or None if the case or comment does not exist.
    """
    case = es_case_repo.get(case_id)
    if not case:
        return None

    comment = es_case_comment_repo.get(comment_id)
    if not comment or comment.case_id != case_id:
        return None

    now = utc_now()
    if "comment" in data:
        comment.comment = data["comment"]
    comment.updated_at = now
    comment.updated_by = data.get("updated_by", dict(KIBANA_USER))

    es_case_comment_repo.save(comment)
    # As with the add: the answer is the case, not the comment.
    from application.es_cases.queries import get_case
    return get_case(case_id)


def delete_comment(case_id: str, comment_id: str) -> bool:
    """Delete a comment from a case.

    Args:
        case_id:    The UUID of the case.
        comment_id: The UUID of the comment to delete.

    Returns:
        True if the comment was deleted, False otherwise.
    """
    case = es_case_repo.get(case_id)
    if not case:
        return False

    comment = es_case_comment_repo.get(comment_id)
    if not comment or comment.case_id != case_id:
        return False

    es_case_comment_repo.delete(comment_id)

    # Removing a comment is a change to the case, as adding one is.
    case.total_comment = len(es_case_comment_repo.get_by_case_id(case_id))
    case.updated_at = utc_now()
    case.updated_by = dict(KIBANA_USER)
    es_case_repo.save(case)

    return True
