"""CrowdStrike Falcon Cases (Messaging Center) command handlers (mutations)."""
from __future__ import annotations

from repository.cs_case_repo import cs_case_repo
from utils.cs_response import (
    build_cs_action_response,
    build_cs_error_response,
)
from utils.dt import utc_now


def add_case_tags(case_id: str, tags: list[str]) -> dict:
    """Add tags to a case.

    Args:
        case_id: ID of the case.
        tags: List of tag strings to add.

    Returns:
        CS action response with affected case ID.
    """
    case = cs_case_repo.get(case_id)
    if not case:
        return build_cs_error_response(404, f"Case {case_id} not found")

    for tag in tags:
        if tag not in case.tags:
            case.tags.append(tag)
    case.last_modified_time = utc_now()
    cs_case_repo.save(case)
    return build_cs_action_response([{"id": case_id}])


def delete_case_tags(case_id: str, tags: list[str]) -> dict:
    """Remove tags from a case.

    Args:
        case_id: ID of the case.
        tags: List of tag strings to remove.

    Returns:
        CS action response with affected case ID.
    """
    case = cs_case_repo.get(case_id)
    if not case:
        return build_cs_error_response(404, f"Case {case_id} not found")

    case.tags = [t for t in case.tags if t not in tags]
    case.last_modified_time = utc_now()
    cs_case_repo.save(case)
    return build_cs_action_response([{"id": case_id}])
