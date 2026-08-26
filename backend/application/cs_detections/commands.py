"""CrowdStrike Falcon Detection command handlers (mutations)."""
from __future__ import annotations

from application import bridge
from domain.cs_detection import CsDetection
from repository.cs_detection_repo import cs_detection_repo
from utils.cs_response import build_cs_action_response
from utils.dt import utc_now


class UnknownAlertActionError(ValueError):
    """Raised for an ``action_parameters`` name CrowdStrike does not define."""


#: The action names CrowdStrike accepts on PATCH /alerts/entities/alerts/v3.
_ALERT_ACTIONS = frozenset({
    "update_status", "assign_to_uuid", "assign_to_user_id", "assign_to_name",
    "unassign", "append_comment", "add_tag", "remove_tag", "remove_tags_by_prefix",
    "show_in_ui",
})


def update_detections(
    ids: list[str],
    action_parameters: list[dict] | None = None,
    status: str | None = None,
    assigned_to_uuid: str | None = None,
    comment: str | None = None,
) -> dict:
    """Update alert status, assignment, tags, and/or add a comment.

    CrowdStrike carries the changes in ``action_parameters`` — a list of
    ``{name, value}`` pairs — rather than as top-level fields. Only the flat
    shape was read, which is not what any real client sends, so a genuine
    request was accepted and changed nothing.

    Args:
        ids:               Composite alert IDs to update.
        action_parameters: CrowdStrike's ``{name, value}`` change list.
        status:            Flat-shape status, retained for existing callers.
        assigned_to_uuid:  Flat-shape assignee, retained for existing callers.
        comment:           Flat-shape comment, retained for existing callers.

    Returns:
        CS action response with affected alert resources.

    Raises:
        UnknownAlertActionError: If an action name is not one CrowdStrike defines.
    """
    changes = _collect_changes(action_parameters, status, assigned_to_uuid, comment)

    affected: list[dict] = []
    for composite_id in ids:
        detection = cs_detection_repo.get(composite_id)
        if not detection:
            continue
        _apply_changes(detection, changes)
        detection.date_updated = utc_now()
        cs_detection_repo.save(detection)
        bridge.cs_detection_changed(detection)
        affected.append({"id": detection.composite_id})
    return build_cs_action_response(affected)


def _collect_changes(
    action_parameters: list[dict] | None,
    status: str | None,
    assigned_to_uuid: str | None,
    comment: str | None,
) -> list[tuple[str, str]]:
    """Normalise both body shapes into an ordered list of (action, value)."""
    changes: list[tuple[str, str]] = []
    if action_parameters is not None and not isinstance(action_parameters, list):
        msg = "action_parameters must be an array of {name, value} objects"
        raise UnknownAlertActionError(msg)

    for parameter in action_parameters or []:
        if not isinstance(parameter, dict):
            msg = "each action parameter must be an object with name and value"
            raise UnknownAlertActionError(msg)
        name = str(parameter.get("name", ""))
        if name not in _ALERT_ACTIONS:
            supported = ", ".join(sorted(_ALERT_ACTIONS))
            msg = f"Unknown action '{name}'. Supported actions: {supported}"
            raise UnknownAlertActionError(msg)
        changes.append((name, str(parameter.get("value", ""))))

    if status is not None:
        changes.append(("update_status", status))
    if assigned_to_uuid is not None:
        changes.append(("assign_to_uuid", assigned_to_uuid))
    if comment is not None:
        changes.append(("append_comment", comment))
    return changes


def _apply_changes(detection: CsDetection, changes: list[tuple[str, str]]) -> None:
    """Apply the collected changes to one alert."""
    for action, value in changes:
        if action == "update_status":
            detection.status = value
        elif action in ("assign_to_uuid", "assign_to_user_id", "assign_to_name"):
            detection.assigned_to_uid = value
        elif action == "unassign":
            detection.assigned_to_uid = ""
        elif action == "add_tag":
            tags = list(detection.tags or [])
            if value not in tags:
                tags.append(value)
            detection.tags = tags
        elif action == "remove_tag":
            detection.tags = [t for t in (detection.tags or []) if t != value]
        elif action == "remove_tags_by_prefix":
            detection.tags = [
                t for t in (detection.tags or []) if not str(t).startswith(value)
            ]
        # append_comment and show_in_ui have no persisted counterpart here;
        # CrowdStrike serves comments from a separate endpoint.
