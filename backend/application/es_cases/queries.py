"""Elastic Security Cases query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.es_case_comment_repo import es_case_comment_repo
from repository.es_case_repo import es_case_repo
from utils.es_pagination import paginate_kibana
from utils.es_response import build_kibana_list_response


def find_cases(
    status: str | None = None,
    tags: list[str] | None = None,
    owner: str | None = None,
    page: int = 1,
    per_page: int = 20,
) -> dict:
    """Find cases with optional filters and Kibana pagination.

    Args:
        status:   Filter by case status (open, in-progress, closed).
        tags:     Filter by tags — case must contain at least one matching tag.
        owner:    Filter by owner application.
        page:     Page number (1-based).
        per_page: Number of items per page.

    Returns:
        Kibana paginated list response.
    """
    records = [asdict(c) for c in es_case_repo.list_all()]

    if status:
        records = [r for r in records if r["status"] == status]
    if tags:
        tag_set = set(tags)
        records = [r for r in records if tag_set & set(r.get("tags", []))]
    if owner:
        records = [r for r in records if r["owner"] == owner]

    page_items, total = paginate_kibana(records, page, per_page)
    return build_kibana_list_response(page_items, page, per_page, total)


def get_case(case_id: str) -> dict | None:
    """Get a single case by its ID.

    Args:
        case_id: The UUID of the case to retrieve.

    Returns:
        Case dict, or None if not found.
    """
    case = es_case_repo.get(case_id)
    if not case:
        return None
    return asdict(case)


def get_case_comments(case_id: str) -> list[dict] | None:
    """List all comments for a case.

    Args:
        case_id: The UUID of the case.

    Returns:
        List of comment dicts, or None if the case does not exist.
    """
    case = es_case_repo.get(case_id)
    if not case:
        return None
    comments = es_case_comment_repo.get_by_case_id(case_id)
    return [asdict(c) for c in comments]


def get_case_activity(case_id: str) -> list[dict] | None:
    """Return case comments as an activity feed.

    Each activity entry includes the comment fields plus an ``action``
    key derived from the comment type.

    Args:
        case_id: The UUID of the case.

    Returns:
        List of activity dicts, or None if the case does not exist.
    """
    case = es_case_repo.get(case_id)
    if not case:
        return None
    comments = es_case_comment_repo.get_by_case_id(case_id)
    activities = []
    for c in comments:
        entry = asdict(c)
        entry["action"] = "comment" if c.type == "user" else c.type
        activities.append(entry)
    return activities


def get_tags() -> list[str]:
    """Return all unique tags across all cases.

    Returns:
        Sorted list of unique tag strings.
    """
    tags: set[str] = set()
    for case in es_case_repo.list_all():
        tags.update(case.tags)
    return sorted(tags)
