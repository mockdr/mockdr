"""Cortex XDR Action query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.xdr_action_repo import xdr_action_repo
from utils.xdr_response import build_xdr_reply


def get_action_status(action_id: str) -> dict | None:
    """Return action status with auto-promotion from pending to completed.

    Simulates asynchronous action completion: if the action is still
    ``pending``, it is promoted to ``completed`` on read.

    Args:
        action_id: The action identifier.

    Returns:
        XDR reply with action data, or None if not found.
    """
    action = xdr_action_repo.get(action_id)
    if not action:
        return None

    # Auto-promote pending actions to completed
    if action.status == "pending":
        action.status = "completed"
        xdr_action_repo.save(action)

    return build_xdr_reply(asdict(action))


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
