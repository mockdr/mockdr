"""Cortex XDR Action query handlers (read-only)."""
from __future__ import annotations

from repository.xdr_action_repo import xdr_action_repo
from utils.xdr_response import build_xdr_reply

#: How the wire spells a status. Cortex answers `data` as a map from endpoint
#: id to one of these; the mock's own vocabulary is lower-case and internal.
#: Only these two can reach a client, because an action is promoted out of
#: `pending` on the read that asks about it.
_WIRE_STATUS = {"completed": "COMPLETED_SUCCESSFULLY", "failed": "FAILED"}


def get_action_status(action_id: str) -> dict | None:
    """Return an action's status, keyed by the endpoint it was aimed at.

    Cortex answers `data` as a map from endpoint id to status — which is
    what a playbook polls: it isolates an endpoint and waits for that
    endpoint's key to reach `COMPLETED_SUCCESSFULLY`. This returned the
    action's own record instead, completed against a recorded reply whose
    keys are three endpoints from someone else's install, so the endpoint the
    client had just acted on was never in the answer and the wait never
    ended.

    Simulates asynchronous completion: an action still `pending` is promoted
    to `completed` on read, so a client that polls once is not left waiting
    for a worker this mock does not have.

    Args:
        action_id: The action identifier.

    Returns:
        XDR reply with the action's per-endpoint status, or None if not found.
    """
    action = xdr_action_repo.get(action_id)
    if not action:
        return None

    # Auto-promote pending actions to completed
    if action.status == "pending":
        action.status = "completed"
        xdr_action_repo.save(action)

    status = _WIRE_STATUS.get(action.status, "COMPLETED_SUCCESSFULLY")
    # Every endpoint the action covers, not just the first: an action created
    # from a `filters` block names as many as the filter selected.
    covered = list(action.endpoint_ids or [action.endpoint_id])
    reply: dict = {"data": dict.fromkeys(covered, status)}
    if status == "FAILED":
        # Only the endpoints that failed carry a reason, and only then does
        # the member appear at all.
        reply["errorReasons"] = {endpoint: {
            "errorData": "",
            "terminated_by": "",
            "errorDescription": "",
            "terminate_result": [],
        } for endpoint in covered}
    return build_xdr_reply(reply)


def get_file_retrieval_details(action_id: str) -> dict | None:
    """Return synthetic file retrieval download details.

    Args:
        action_id: The action identifier.

    Returns:
        XDR reply with download link, or None if not found.
    """
    action = xdr_action_repo.get(action_id)
    if not action:
        return None

    return build_xdr_reply({
        "action_id": action_id,
        "endpoint_id": action.endpoint_id,
        "file_link": f"https://xdr-mock.acmecorp.internal/files/{action_id}/download",
        "file_name": "retrieved_file.zip",
        "file_size": 1048576,
        "status": "ready",
    })
