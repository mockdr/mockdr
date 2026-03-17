"""CrowdStrike Falcon Cases (Messaging Center) command handlers (mutations)."""
from __future__ import annotations

import uuid as _uuid

from domain.cs_case import CsCase
from infrastructure.seeders.cs_shared import CS_CID
from repository.cs_case_repo import cs_case_repo
from utils.cs_response import (
    build_cs_action_response,
    build_cs_entity_response,
    build_cs_error_response,
)
from utils.dt import utc_now


def create_case(body: dict) -> dict:
    """Create a new support case.

    Args:
        body: Request body with ``title``, ``body``, ``type``, ``detections``, ``incidents``.

    Returns:
        CS entity response with the newly created case.
    """
    now = utc_now()
    case = CsCase(
        id=str(_uuid.uuid4()),
        cid=CS_CID,
        title=body.get("title", "Untitled Case"),
        body=body.get("body", ""),
        type=body.get("type", "standard"),
        detections=body.get("detections", []),
        incidents=body.get("incidents", []),
        status="open",
        created_time=now,
        last_modified_time=now,
    )
    cs_case_repo.save(case)
    from dataclasses import asdict
    return build_cs_entity_response([asdict(case)])


def update_case(case_id: str, body: dict) -> dict:
    """Update an existing case.

    Args:
        case_id: ID of the case to update.
        body: Fields to update (title, body, status).

    Returns:
        CS entity response with the updated case.
    """
    case = cs_case_repo.get(case_id)
    if not case:
        return build_cs_error_response(404, f"Case {case_id} not found")

    for field in ("title", "body", "status"):
        if field in body:
            setattr(case, field, body[field])
    case.last_modified_time = utc_now()
    cs_case_repo.save(case)
    from dataclasses import asdict
    return build_cs_entity_response([asdict(case)])


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
