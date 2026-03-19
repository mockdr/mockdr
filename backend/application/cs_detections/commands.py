"""CrowdStrike Falcon Detection command handlers (mutations)."""
from __future__ import annotations

from repository.cs_detection_repo import cs_detection_repo
from utils.cs_response import build_cs_action_response
from utils.dt import utc_now


def update_detections(
    ids: list[str],
    status: str | None = None,
    assigned_to_uuid: str | None = None,
    comment: str | None = None,
) -> dict:
    """Update detection status, assignment, and/or add a comment.

    Args:
        ids:              List of composite detection IDs to update.
        status:           New status value (e.g. ``"in_progress"``, ``"closed"``,
                          ``"true_positive"``), or None to leave unchanged.
        assigned_to_uuid: UUID of the user to assign, or None to leave unchanged.
        comment:          Comment text to attach, or None to skip. Comments are
                          not persisted on the domain object since the real CS API
                          returns them via a separate endpoint; this is a no-op
                          placeholder.

    Returns:
        CS action response with affected detection resources.
    """
    affected: list[dict] = []
    for composite_id in ids:
        detection = cs_detection_repo.get(composite_id)
        if not detection:
            continue
        if status is not None:
            detection.status = status
        if assigned_to_uuid is not None:
            detection.assigned_to_uid = assigned_to_uuid
        detection.date_updated = utc_now()
        cs_detection_repo.save(detection)
        affected.append({"id": detection.composite_id})
    return build_cs_action_response(affected)
