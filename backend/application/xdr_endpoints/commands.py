"""Cortex XDR Endpoint command handlers (mutations)."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from domain.xdr_action import XdrAction
from repository.xdr_action_repo import xdr_action_repo
from repository.xdr_endpoint_repo import xdr_endpoint_repo
from utils.xdr_response import build_xdr_reply


def _epoch_ms() -> int:
    """Return current time as epoch milliseconds."""
    return int(datetime.now(UTC).timestamp() * 1000)


def _create_action(endpoint_id: str, action_type: str) -> XdrAction:
    """Create and persist an XDR action record.

    Args:
        endpoint_id: Target endpoint identifier.
        action_type: Action type string.

    Returns:
        The newly created action.
    """
    action = XdrAction(
        action_id=str(uuid.uuid4()),
        action_type=action_type,
        status="pending",
        endpoint_id=endpoint_id,
        creation_time=_epoch_ms(),
    )
    xdr_action_repo.save(action)
    return action


def isolate_endpoint(endpoint_id: str) -> dict | None:
    """Isolate an endpoint from the network.

    Args:
        endpoint_id: The endpoint identifier.

    Returns:
        XDR reply with action ID, or None if endpoint not found.
    """
    endpoint = xdr_endpoint_repo.get(endpoint_id)
    if not endpoint:
        return None

    endpoint.is_isolated = "isolated"
    endpoint.isolated_date = _epoch_ms()
    xdr_endpoint_repo.save(endpoint)

    action = _create_action(endpoint_id, "isolate")
    return build_xdr_reply({"action_id": action.action_id})


def unisolate_endpoint(endpoint_id: str) -> dict | None:
    """Release an endpoint from network isolation.

    Args:
        endpoint_id: The endpoint identifier.

    Returns:
        XDR reply with action ID, or None if endpoint not found.
    """
    endpoint = xdr_endpoint_repo.get(endpoint_id)
    if not endpoint:
        return None

    endpoint.is_isolated = "unisolated"
    endpoint.isolated_date = None
    xdr_endpoint_repo.save(endpoint)

    action = _create_action(endpoint_id, "unisolate")
    return build_xdr_reply({"action_id": action.action_id})


def scan_endpoint(endpoint_id: str) -> dict | None:
    """Initiate a scan on an endpoint.

    Args:
        endpoint_id: The endpoint identifier.

    Returns:
        XDR reply with action ID, or None if endpoint not found.
    """
    endpoint = xdr_endpoint_repo.get(endpoint_id)
    if not endpoint:
        return None

    endpoint.scan_status = "in_progress"
    xdr_endpoint_repo.save(endpoint)

    action = _create_action(endpoint_id, "scan")
    return build_xdr_reply({"action_id": action.action_id})


def delete_endpoints(endpoint_ids: list[str]) -> dict:
    """Delete one or more endpoints.

    Args:
        endpoint_ids: List of endpoint identifiers to delete.

    Returns:
        XDR reply confirming success.
    """
    for eid in endpoint_ids:
        xdr_endpoint_repo.delete(eid)
    return build_xdr_reply(True)


def update_agent_name(endpoint_id: str, alias: str) -> dict | None:
    """Update the alias (display name) of an endpoint.

    Args:
        endpoint_id: The endpoint identifier.
        alias: New alias string.

    Returns:
        XDR reply confirming success, or None if endpoint not found.
    """
    endpoint = xdr_endpoint_repo.get(endpoint_id)
    if not endpoint:
        return None

    endpoint.alias = alias
    xdr_endpoint_repo.save(endpoint)
    return build_xdr_reply(True)


def terminate_process(endpoint_id: str, params: dict) -> dict | None:
    """Create a terminate-process action on an endpoint.

    Args:
        endpoint_id: The endpoint identifier.
        params: Dict with process details (``pid``, ``process_name``).

    Returns:
        XDR reply with action ID, or None if endpoint not found.
    """
    endpoint = xdr_endpoint_repo.get(endpoint_id)
    if not endpoint:
        return None

    action = _create_action(endpoint_id, "terminate_process")
    action.result = {"pid": params.get("pid"), "process_name": params.get("process_name")}
    xdr_action_repo.save(action)
    return build_xdr_reply({"action_id": action.action_id})


def quarantine_file(endpoint_id: str, params: dict) -> dict | None:
    """Create a quarantine-file action on an endpoint.

    Args:
        endpoint_id: The endpoint identifier.
        params: Dict with file details (``file_path``, ``file_hash``).

    Returns:
        XDR reply with action ID, or None if endpoint not found.
    """
    endpoint = xdr_endpoint_repo.get(endpoint_id)
    if not endpoint:
        return None

    action = _create_action(endpoint_id, "quarantine")
    action.result = {"file_path": params.get("file_path"), "file_hash": params.get("file_hash")}
    xdr_action_repo.save(action)
    return build_xdr_reply({"action_id": action.action_id})


def restore_file(endpoint_id: str, params: dict) -> dict | None:
    """Create a restore-file action on an endpoint.

    Args:
        endpoint_id: The endpoint identifier.
        params: Dict with file details (``file_hash``).

    Returns:
        XDR reply with action ID, or None if endpoint not found.
    """
    endpoint = xdr_endpoint_repo.get(endpoint_id)
    if not endpoint:
        return None

    action = _create_action(endpoint_id, "restore")
    action.result = {"file_hash": params.get("file_hash")}
    xdr_action_repo.save(action)
    return build_xdr_reply({"action_id": action.action_id})


def file_retrieval(endpoint_id: str, params: dict) -> dict | None:
    """Create a file-retrieval action on an endpoint.

    Args:
        endpoint_id: The endpoint identifier.
        params: Dict with file details (``file_path``).

    Returns:
        XDR reply with action ID, or None if endpoint not found.
    """
    endpoint = xdr_endpoint_repo.get(endpoint_id)
    if not endpoint:
        return None

    action = _create_action(endpoint_id, "file_retrieval")
    action.result = {"file_path": params.get("file_path")}
    xdr_action_repo.save(action)
    return build_xdr_reply({"action_id": action.action_id})
