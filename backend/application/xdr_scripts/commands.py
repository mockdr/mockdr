"""Cortex XDR Script command handlers (mutations)."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from domain.xdr_action import XdrAction
from repository.xdr_action_repo import xdr_action_repo
from repository.xdr_script_repo import xdr_script_repo
from utils.xdr_response import build_xdr_reply


def run_script(endpoint_ids: list[str], script_id: str, params: dict) -> dict | None:
    """Execute a script on one or more endpoints.

    Creates a pending action record for each endpoint.

    Args:
        endpoint_ids: List of target endpoint identifiers.
        script_id: The script identifier to run.
        params: Additional parameters for the script execution.

    Returns:
        XDR reply with action ID, or None if script not found.
    """
    script = xdr_script_repo.get(script_id)
    if not script:
        return None

    action_id = str(uuid.uuid4())
    now_ms = int(datetime.now(UTC).timestamp() * 1000)

    # Create one action per endpoint, all sharing the same action_id prefix
    for eid in endpoint_ids:
        action = XdrAction(
            action_id=f"{action_id}_{eid}" if len(endpoint_ids) > 1 else action_id,
            action_type="script_run",
            status="pending",
            endpoint_id=eid,
            creation_time=now_ms,
            result={
                "script_id": script_id,
                "script_name": script.name,
                "parameters": params.get("parameters", {}),
                "timeout": params.get("timeout", 600),
            },
        )
        xdr_action_repo.save(action)

    return build_xdr_reply({
        "action_id": action_id,
        "endpoints_count": len(endpoint_ids),
    })
