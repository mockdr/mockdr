"""Elastic Security endpoint command handlers (mutations)."""
from __future__ import annotations

import uuid
from dataclasses import asdict

from domain.es_action_response import EsActionResponse
from repository.es_action_response_repo import es_action_response_repo
from repository.es_endpoint_repo import es_endpoint_repo
from utils.dt import utc_now


def _create_action(
    agent_id: str,
    action: str,
    comment: str = "",
    parameters: dict | None = None,
) -> dict:
    """Create an action response record and persist it.

    Args:
        agent_id:   ID of the target endpoint.
        action:     Action type string (e.g. ``"isolate"``).
        comment:    Operator comment describing the reason.
        parameters: Additional action parameters.

    Returns:
        The new action response as a dict.
    """
    now = utc_now()
    action_resp = EsActionResponse(
        id=str(uuid.uuid4()),
        agent_id=agent_id,
        action=action,
        status="pending",
        started_at=now,
        created_by="analyst@acmecorp.internal",
        parameters=parameters or {},
    )
    if comment:
        action_resp.parameters["comment"] = comment
    es_action_response_repo.save(action_resp)
    return asdict(action_resp)


def isolate_endpoint(agent_id: str, comment: str = "") -> dict | None:
    """Isolate an endpoint from the network.

    Sets ``isolation_status`` to ``"isolated"`` and creates a pending action.

    Args:
        agent_id: ID of the target endpoint.
        comment:  Operator comment.

    Returns:
        Action response dict, or None if endpoint not found.
    """
    ep = es_endpoint_repo.get(agent_id)
    if not ep:
        return None
    ep.isolation_status = "isolated"
    es_endpoint_repo.save(ep)
    return _create_action(agent_id, "isolate", comment)


def unisolate_endpoint(agent_id: str, comment: str = "") -> dict | None:
    """Release an endpoint from network isolation.

    Sets ``isolation_status`` to ``"normal"``.

    Args:
        agent_id: ID of the target endpoint.
        comment:  Operator comment.

    Returns:
        Action response dict, or None if endpoint not found.
    """
    ep = es_endpoint_repo.get(agent_id)
    if not ep:
        return None
    ep.isolation_status = "normal"
    es_endpoint_repo.save(ep)
    return _create_action(agent_id, "unisolate", comment)


def kill_process(agent_id: str, params: dict) -> dict | None:
    """Kill a process on the endpoint.

    Args:
        agent_id: ID of the target endpoint.
        params:   Request body with process parameters.

    Returns:
        Action response dict, or None if endpoint not found.
    """
    ep = es_endpoint_repo.get(agent_id)
    if not ep:
        return None
    return _create_action(agent_id, "kill-process", parameters=params)


def scan_endpoint(agent_id: str, comment: str = "") -> dict | None:
    """Trigger a scan on the endpoint.

    Args:
        agent_id: ID of the target endpoint.
        comment:  Operator comment.

    Returns:
        Action response dict, or None if endpoint not found.
    """
    ep = es_endpoint_repo.get(agent_id)
    if not ep:
        return None
    return _create_action(agent_id, "scan", comment)


def list_actions(agent_id: str | None = None) -> list[dict]:
    """List action responses, optionally filtered by agent ID.

    Args:
        agent_id: If provided, filter to actions for this endpoint only.

    Returns:
        List of action response dicts.
    """
    if agent_id:
        actions = es_action_response_repo.get_by_agent_id(agent_id)
    else:
        actions = es_action_response_repo.list_all()
    return [asdict(a) for a in actions]


def get_action(action_id: str) -> dict | None:
    """Get a single action response by ID.

    Args:
        action_id: The action response ID to look up.

    Returns:
        Action response dict, or None if not found.
    """
    action = es_action_response_repo.get(action_id)
    if not action:
        return None
    return asdict(action)
