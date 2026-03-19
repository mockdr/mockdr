"""Cortex XDR XQL query handlers (read-only)."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from domain.xdr_xql_query import XdrXqlQuery
from repository.xdr_xql_query_repo import xdr_xql_query_repo
from utils.xdr_response import build_xdr_reply


def start_query(query_string: str) -> dict:
    """Create an XQL query execution record and return its query_id.

    Args:
        query_string: The XQL query string to execute.

    Returns:
        XDR reply with the new ``query_id``.
    """
    query_id = str(uuid.uuid4())
    now_ms = int(datetime.now(UTC).timestamp() * 1000)

    query = XdrXqlQuery(
        query_id=query_id,
        status="pending",
        query=query_string,
        results=[],
        execution_time=now_ms,
    )
    xdr_xql_query_repo.save(query)

    return build_xdr_reply({"query_id": query_id})


def get_query_results(query_id: str) -> dict | None:
    """Return canned results for an XQL query.

    Auto-promotes status from ``pending`` to ``completed``.

    Args:
        query_id: The query identifier.

    Returns:
        XDR reply with query results, or None if not found.
    """
    query = xdr_xql_query_repo.get(query_id)
    if not query:
        return None

    # Auto-promote pending queries to completed with canned results
    if query.status == "pending":
        query.status = "completed"
        query.results = [
            {
                "_time": query.execution_time,
                "agent_hostname": "ACME-WS-001",
                "agent_ip_addresses": "10.10.1.100",
                "action_type": "PROCESS_EXECUTION",
                "actor_process_image_name": "cmd.exe",
                "actor_process_command_line": "cmd.exe /c whoami",
            },
            {
                "_time": query.execution_time,
                "agent_hostname": "ACME-SRV-001",
                "agent_ip_addresses": "10.10.2.50",
                "action_type": "FILE_WRITE",
                "actor_process_image_name": "python3",
                "actor_process_command_line": "python3 script.py",
            },
        ]
        xdr_xql_query_repo.save(query)

    return build_xdr_reply({
        "status": query.status,
        "number_of_results": len(query.results),
        "query_cost": {"376699223": 0.001},
        "remaining_quota": 99.999,
        "results": {"data": query.results},
    })


def get_quota() -> dict:
    """Return synthetic XQL query quota information.

    Returns:
        XDR reply with quota data.
    """
    return build_xdr_reply({
        "eval_quota": {
            "maxSize": 100,
            "usedSize": 0.001,
        },
        "export_quota": {
            "maxSize": 100,
            "usedSize": 0,
        },
    })
