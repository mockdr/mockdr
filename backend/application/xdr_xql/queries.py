"""Cortex XDR XQL query handlers (read-only).

What the real API does, and where it is written down:

- ``start_xql_query`` answers the execution id as a bare string in
  ``reply`` — ``{"reply": "<execution_id>"}`` — which the client passes back
  as ``query_id`` (Palo Alto, "Run XQL query APIs"; XSOAR CoreXQLApiModule
  ``CoreClient.start_xql_query``: ``execution_id = res.get("reply", "")``).
- ``get_query_results`` answers ``status`` as one of ``PENDING``, ``SUCCESS``
  or ``FAIL``. ``pending_flag`` (default true) returns at once, with
  ``PENDING`` while the query runs; false waits until the results are ready.
  At most 1,000 results come inline; above that ``results`` carries a
  ``stream_id`` for ``get_query_results_stream`` instead of ``data``. ``limit``
  caps how many come back.
- ``get_quota`` answers numbers: ``license_quota``, ``eval_quota`` and the
  query counters are integers, ``used_quota`` a number (Palo Alto, "Run XQL
  query APIs"; XSOAR CoreXQLApiModule_test ``test_get_xql_quota_command``).
"""
from __future__ import annotations

import gzip
import json
import uuid
from datetime import UTC, datetime

from domain.xdr_xql_query import XdrXqlQuery
from repository.xdr_xql_query_repo import xdr_xql_query_repo
from utils.xdr_response import build_xdr_reply

#: The most results ``get_query_results`` answers inline; a larger result set
#: is handed out as a stream (Palo Alto, "Get XQL Query Results").
INLINE_RESULT_LIMIT = 1000

#: The quota the tenant is licensed for, in query units.
_LICENSE_QUOTA = 1000

#: What one canned query costs, in query units, keyed by the tenant id the
#: XSOAR recordings carry.
_QUERY_COST = {"376699223": 0.001}


def start_query(query_string: str) -> dict:
    """Create an XQL query execution record and return its execution id.

    Args:
        query_string: The XQL query string to execute.

    Returns:
        XDR reply whose ``reply`` is the execution id itself, a string.
    """
    query_id = uuid.uuid4().hex
    now_ms = int(datetime.now(UTC).timestamp() * 1000)

    query = XdrXqlQuery(
        query_id=query_id,
        status="PENDING",
        query=query_string,
        results=[],
        execution_time=now_ms,
    )
    xdr_xql_query_repo.save(query)

    return build_xdr_reply(query_id)


def _canned_results(query: XdrXqlQuery) -> list[dict]:
    """The rows every query produces — the mock runs no XQL engine."""
    return [
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


def _used_quota() -> float:
    """Query units spent by every query that has finished."""
    done = [q for q in xdr_xql_query_repo.list_all() if q.status == "SUCCESS"]
    return round(len(done) * sum(_QUERY_COST.values()), 6)


def get_query_results(
    query_id: str, *, pending_flag: bool = True, limit: int | None = None,
) -> dict | None:
    """Return an XQL query's status and, once it has finished, its results.

    A query is still running when it is first asked about: with
    ``pending_flag`` true (the default, and what the XSOAR integration sends)
    that read answers ``PENDING`` and the query finishes behind it, so the
    next poll answers ``SUCCESS``. With ``pending_flag`` false the call waits,
    as the real one does, and answers ``SUCCESS`` at once.

    Args:
        query_id:     The execution id ``start_xql_query`` answered.
        pending_flag: Return at once (true) or wait for the results (false).
        limit:        The most result rows to return.

    Returns:
        XDR reply with the query's status and results, or None if not found.
    """
    query = xdr_xql_query_repo.get(query_id)
    if not query:
        return None

    if query.status == "PENDING":
        query.status = "SUCCESS"
        query.results = _canned_results(query)
        xdr_xql_query_repo.save(query)
        if pending_flag:
            return build_xdr_reply({
                "status": "PENDING",
                "number_of_results": 0,
                "query_cost": {},
                "remaining_quota": float(_LICENSE_QUOTA) - _used_quota(),
                "results": {},
            })

    rows = query.results if limit is None else query.results[:limit]
    results: dict
    if len(rows) > INLINE_RESULT_LIMIT:
        if not query.stream_id:
            query.stream_id = f"{query.query_id}_stream"
            xdr_xql_query_repo.save(query)
        results = {"stream_id": query.stream_id}
    else:
        results = {"data": rows}

    return build_xdr_reply({
        "status": query.status,
        "number_of_results": len(query.results),
        "query_cost": dict(_QUERY_COST),
        "remaining_quota": float(_LICENSE_QUOTA) - _used_quota(),
        "results": results,
    })


def get_query_results_stream(stream_id: str, *, gzip_compressed: bool) -> bytes | None:
    """The full result set of a query too large to answer inline.

    One JSON object per line, gzip-compressed when the client asks for it —
    the XSOAR integration sends ``is_gzip_compressed: true`` and reads the
    body as ``gzip.decompress(data).decode()`` split on newlines, one
    ``json.loads`` per line (CoreXQLApiModule ``get_query_result_stream`` and
    ``get_xql_query_results_polling_command``).

    Args:
        stream_id:       The ``stream_id`` ``get_query_results`` answered.
        gzip_compressed: Whether to gzip the body.

    Returns:
        The body, or None if no query has that stream.
    """
    query = next(
        (q for q in xdr_xql_query_repo.list_all() if stream_id and q.stream_id == stream_id),
        None,
    )
    if query is None:
        return None
    body = "\n".join(json.dumps(row, separators=(",", ":")) for row in query.results).encode()
    return gzip.compress(body) if gzip_compressed else body


def get_quota() -> dict:
    """Return the tenant's XQL query quota.

    Returns:
        XDR reply with quota data.
    """
    running = [q for q in xdr_xql_query_repo.list_all() if q.status == "PENDING"]
    return build_xdr_reply({
        "license_quota": _LICENSE_QUOTA,
        "additional_purchased_quota": 0,
        "used_quota": _used_quota(),
        "eval_quota": 0,
        "current_concurrent_active_queries": {q.query_id: "0" for q in running},
        "current_concurrent_active_queries_count": len(running),
        "max_daily_concurrent_active_query_count": len(running),
        "total_daily_concurrent_rejected_queries": 0,
        "total_daily_running_queries": len(xdr_xql_query_repo.list_all()),
    })
