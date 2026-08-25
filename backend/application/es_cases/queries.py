"""Elastic Security Cases query handlers (read-only)."""
from __future__ import annotations

from repository.es_case_comment_repo import es_case_comment_repo
from repository.es_case_repo import es_case_repo
from utils.es_case_serde import serialise_case, serialise_comment, status_counts
from utils.es_pagination import paginate_kibana
from utils.es_response import build_kibana_cases_response
from utils.serde import record_dict

#: Sort fields the Cases API accepts, mapped to the stored field.
_CASE_SORT_FIELDS = {
    "createdAt": "created_at",
    "created_at": "created_at",
    "updatedAt": "updated_at",
    "updated_at": "updated_at",
    "closedAt": "closed_at",
    "closed_at": "closed_at",
    "title": "title",
    "status": "status",
    "severity": "severity",
}


def find_cases(
    status: str | None = None,
    tags: list[str] | None = None,
    owner: str | None = None,
    page: int = 1,
    per_page: int = 20,
    severity: str | None = None,
    search: str | None = None,
    reporters: list[str] | None = None,
    sort_field: str | None = None,
    sort_order: str = "desc",
) -> dict:
    """Find cases with optional filters and Kibana pagination.

    ``severity``, ``search``, ``reporters``, ``sortField`` and ``sortOrder``
    are all documented on this endpoint and were accepted and ignored, so a
    filtered request came back as the full unfiltered list.

    Args:
        status:     Filter by case status (open, in-progress, closed).
        tags:       Filter by tags — case must contain at least one match.
        owner:      Filter by owner application.
        page:       Page number (1-based).
        per_page:   Number of items per page.
        severity:   Filter by case severity.
        search:     Free-text search across title and description.
        reporters:  Filter by the username that created the case.
        sort_field: Field to sort by.
        sort_order: ``asc`` or ``desc``.

    Returns:
        Kibana paginated list response.
    """
    records = [record_dict(c) for c in es_case_repo.list_all()]

    if status:
        records = [r for r in records if r["status"] == status]
    if severity:
        records = [r for r in records if r.get("severity") == severity]
    if tags:
        tag_set = set(tags)
        records = [r for r in records if tag_set & set(r.get("tags", []))]
    if owner:
        records = [r for r in records if r["owner"] == owner]
    if reporters:
        wanted = set(reporters)
        records = [
            r for r in records
            if (r.get("created_by") or {}).get("username") in wanted
        ]
    if search:
        needle = search.lower()
        records = [
            r for r in records
            if needle in str(r.get("title", "")).lower()
            or needle in str(r.get("description", "")).lower()
        ]

    field = _CASE_SORT_FIELDS.get(sort_field or "", "created_at")
    records.sort(key=lambda r: str(r.get(field) or ""), reverse=sort_order != "asc")

    counts = status_counts(records)
    page_items, total = paginate_kibana(records, page, per_page)
    return build_kibana_cases_response(
        [serialise_case(r) for r in page_items], page, per_page, total, counts,
    )


def get_case(case_id: str) -> dict | None:
    """Get a single case by its ID, comments and all.

    Kibana fills ``comments`` when a case is fetched by its id and leaves it
    empty in ``_find`` — where only ``totalComment`` says how many there are.
    The mock left it empty in both, so a client that read the case it had
    just commented on saw no comment.

    Args:
        case_id: The UUID of the case to retrieve.

    Returns:
        Case dict, or None if not found.
    """
    case = es_case_repo.get(case_id)
    if not case:
        return None
    rendered = serialise_case(record_dict(case))
    rendered["comments"] = [
        serialise_comment(record_dict(comment))
        for comment in es_case_comment_repo.get_by_case_id(case_id)
    ]
    return rendered


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
    return [serialise_comment(record_dict(c)) for c in comments]


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
        entry = record_dict(c)
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
