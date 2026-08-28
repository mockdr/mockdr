"""Cortex XDR Script command handlers (mutations)."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from domain.xdr_action import XdrAction
from repository.xdr_action_repo import xdr_action_repo
from repository.xdr_script_repo import xdr_script_repo
from utils.xdr_response import build_xdr_reply


def run_script(endpoint_ids: list[str], script_id: str, params: dict) -> dict | None:
    """Run a script on every endpoint the request named.

    Two things were broken, and together they broke the whole pattern a
    playbook uses — run a script, poll for its result. The route read
    `endpoint_id_list` where Cortex requires a `filters` block, so a
    documented call selected nobody, created no action at all, and still
    answered an `action_id`; polling that id then answered
    `500 Action … not found`. And for more than one endpoint the records were
    keyed `<action_id>_<endpoint>` while the reply carried the bare id, so
    that id named nothing either. One action covers the set now, which is
    what Cortex answers and what `get_script_execution_status` needs to find.

    Args:
        endpoint_ids: Target endpoints, resolved from the request.
        script_id: The script identifier to run.
        params: Additional parameters for the script execution.

    Returns:
        XDR reply with the action id, or None if the script or the endpoints
        are not this tenant's.
    """
    script = xdr_script_repo.get(script_id)
    if not script or not endpoint_ids:
        return None

    action = XdrAction(
        action_id=str(uuid.uuid4()),
        action_type="script_run",
        status="pending",
        endpoint_id=endpoint_ids[0],
        endpoint_ids=list(endpoint_ids),
        creation_time=int(datetime.now(UTC).timestamp() * 1000),
        result={
            "script_uid": script_id,
            "script_name": script.name,
            "parameters": params.get("parameters", {}),
            "timeout": params.get("timeout", 600),
        },
    )
    xdr_action_repo.save(action)

    return build_xdr_reply({
        "action_id": action.action_id,
        "endpoints_count": str(len(endpoint_ids)),
    })
