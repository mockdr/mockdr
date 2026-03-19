"""Cortex XDR Script query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.xdr_action_repo import xdr_action_repo
from repository.xdr_script_repo import xdr_script_repo
from utils.xdr_response import build_xdr_list_reply, build_xdr_reply


def get_scripts(request_data: dict) -> dict:
    """List scripts with optional filtering and pagination.

    Args:
        request_data: The ``request_data`` dict from the POST body.

    Returns:
        XDR list reply with matching scripts.
    """
    all_scripts = [asdict(s) for s in xdr_script_repo.list_all()]

    script_type = request_data.get("script_type")
    if script_type:
        values = script_type if isinstance(script_type, list) else [script_type]
        all_scripts = [s for s in all_scripts if s["script_type"] in values]

    total = len(all_scripts)
    search_from = request_data.get("search_from", 0)
    search_to = request_data.get("search_to", search_from + 100)
    page = all_scripts[search_from:search_to]

    return build_xdr_list_reply(page, total_count=total, key="scripts")


def get_script_metadata(script_id: str) -> dict | None:
    """Return metadata for a single script.

    Args:
        script_id: The script identifier.

    Returns:
        XDR reply with script details, or None if not found.
    """
    script = xdr_script_repo.get(script_id)
    if not script:
        return None
    return build_xdr_reply(asdict(script))


def get_execution_status(action_id: str) -> dict | None:
    """Return the execution status for a script run action.

    Auto-promotes status from ``pending`` to ``completed`` to simulate
    asynchronous execution.

    Args:
        action_id: The action identifier.

    Returns:
        XDR reply with action status, or None if not found.
    """
    action = xdr_action_repo.get(action_id)
    if not action:
        return None

    # Auto-promote pending actions to completed
    if action.status == "pending":
        action.status = "completed"
        xdr_action_repo.save(action)

    return build_xdr_reply(asdict(action))


def get_execution_results(action_id: str) -> dict | None:
    """Return canned execution results for a script run action.

    Args:
        action_id: The action identifier.

    Returns:
        XDR reply with execution results, or None if not found.
    """
    action = xdr_action_repo.get(action_id)
    if not action:
        return None

    results = [
        {
            "endpoint_id": action.endpoint_id,
            "endpoint_name": "xdr-endpoint",
            "status": "COMPLETED_SUCCESSFULLY",
            "return_value": "Script executed successfully",
            "standard_output": "OK\n",
            "standard_error": "",
            "retention_date": None,
        },
    ]

    return build_xdr_list_reply(results, total_count=len(results))
