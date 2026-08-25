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


def update_agent_name(request_data: dict, alias: str) -> dict | None:
    """Set the alias of every endpoint the request's ``filters`` select.

    Cortex names the target of this call with a ``filters`` block, the same
    one the read routes take — not with an ``endpoint_id``. Reading an id
    that the documented body never carries meant the call answered 500
    ``Endpoint  not found`` to every well-formed request.

    Args:
        request_data: The ``request_data`` dict from the POST body.
        alias: New alias string.

    Returns:
        XDR reply confirming success, or None if the filters select nothing.
    """
    from application.xdr_endpoints.queries import select_endpoints

    matched = select_endpoints(request_data)
    if not matched:
        return None

    for endpoint in matched:
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


def tag_endpoints(body: dict, *, assign: bool) -> dict:
    """Add or remove one tag on every endpoint the body names.

    Cortex's client sends the endpoints in ``context.lcaas_id`` and narrows
    them with ``request_data.filters``; either may be absent, and what both
    name is intersected. The reply is empty, as the vendor's own sample is.

    Args:
        body: The whole POST body, ``context`` included.
        assign: ``True`` to add the tag, ``False`` to remove it.

    Returns:
        XDR reply with an empty body.
    """
    from application.xdr_endpoints.queries import select_endpoints

    request_data = body.get("request_data") or {}
    matched = select_endpoints(request_data)
    lcaas = (body.get("context") or {}).get("lcaas_id")
    if lcaas:
        matched = [e for e in matched if e.endpoint_id in lcaas]

    tag = str(request_data.get("tag") or "")
    for endpoint in matched:
        tags = list(endpoint.endpoint_tags)
        if assign and tag and tag not in tags:
            tags.append(tag)
        elif not assign and tag in tags:
            tags.remove(tag)
        endpoint.endpoint_tags = tags
        xdr_endpoint_repo.save(endpoint)
    return build_xdr_reply({})
