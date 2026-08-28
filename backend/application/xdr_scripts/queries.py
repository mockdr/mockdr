"""Cortex XDR Script query handlers (read-only)."""
from __future__ import annotations

from repository.xdr_action_repo import xdr_action_repo
from repository.xdr_script_repo import xdr_script_repo
from utils.serde import record_dict
from utils.xdr_response import build_xdr_list_reply, build_xdr_reply


def _script_to_api(record: dict) -> dict:
    """Rename the stored ``script_id`` to the ``script_uid`` XDR reports.

    The scripts API identifies a script by ``script_uid`` everywhere — in the
    listing, in ``get_script_metadata`` and in ``run_script`` — so a client
    reading ``script_uid`` off this response found nothing and had no id to
    run.
    """
    if "script_id" not in record:
        return record
    return {
        ("script_uid" if key == "script_id" else key): value
        for key, value in record.items()
    }



def get_scripts(request_data: dict) -> dict:
    """List scripts with optional filtering and pagination.

    Args:
        request_data: The ``request_data`` dict from the POST body.

    Returns:
        XDR list reply with matching scripts.
    """
    all_scripts = [_script_to_api(record_dict(s)) for s in xdr_script_repo.list_all()]

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
    return build_xdr_reply(_script_to_api(record_dict(script)))


def get_execution_status(action_id: str) -> dict | None:
    """Return the execution status for a script run action.

    Cortex answers a tally: how many endpoints are pending, in progress,
    completed, failed. This answered the stored action record instead, whose
    field names are none of those — so the recorded shape filled the reply
    with zeros and a playbook polling
    `endpoints_completed_successfully == 2` waited for ever on a run that had
    finished.

    Auto-promotes status from ``pending`` to ``completed`` to simulate
    asynchronous execution.

    Args:
        action_id: The action identifier.

    Returns:
        XDR reply with the tally, or None if not found.
    """
    action = xdr_action_repo.get(action_id)
    if not action:
        return None

    # Auto-promote pending actions to completed
    if action.status == "pending":
        action.status = "completed"
        xdr_action_repo.save(action)

    covered = list(action.endpoint_ids or [action.endpoint_id])
    done = action.status == "completed"
    return build_xdr_reply({
        "general_status": "COMPLETED_SUCCESSFULLY" if done else "IN_PROGRESS",
        "endpoints_completed_successfully": len(covered) if done else 0,
        "endpoints_in_progress": 0 if done else len(covered),
        "endpoints_pending": 0,
        "endpoints_failed": 0,
        "endpoints_expired": 0,
        "endpoints_canceled": 0,
        "endpoints_aborted": 0,
        "endpoints_pending_abort": 0,
        "endpoints_timeout": 0,
        "error_message": "",
    })


def get_execution_results(action_id: str) -> dict | None:
    """Return the results of a script run, one row per endpoint it ran on.

    The row was canned — one endpoint called `xdr-endpoint`, whatever the run
    covered — and named its members `status` and `return_value` where Cortex
    names them `execution_status` and `standard_output`, beside a
    `script_name` and a `date_created` the reply left blank. The run knows
    all of it.

    Args:
        action_id: The action identifier.

    Returns:
        XDR reply with the results, or None if not found.
    """
    from repository.xdr_endpoint_repo import xdr_endpoint_repo  # noqa: PLC0415

    action = xdr_action_repo.get(action_id)
    if not action:
        return None

    detail = action.result or {}
    script = xdr_script_repo.get(str(detail.get("script_uid") or ""))
    results = []
    for endpoint_id in action.endpoint_ids or [action.endpoint_id]:
        endpoint = xdr_endpoint_repo.get(endpoint_id)
        results.append({
            "endpoint_id": endpoint_id,
            "endpoint_name": endpoint.endpoint_name if endpoint else "",
            "endpoint_ip_address": (
                endpoint.ip[0] if endpoint and endpoint.ip else ""
            ),
            "endpoint_status": endpoint.endpoint_status if endpoint else "",
            "domain": endpoint.domain if endpoint else "",
            "execution_status": "COMPLETED_SUCCESSFULLY",
            "standard_output": "OK\n",
            "retrieved_files": 0,
            "failed_files": 0,
            "retention_date": None,
        })

    return build_xdr_reply({
        "script_name": script.name if script else "",
        "script_description": script.description if script else "",
        "script_parameters": detail.get("parameters") or [],
        "date_created": action.creation_time,
        "error_message": "",
        "scope": "all",
        "results": results,
    })
