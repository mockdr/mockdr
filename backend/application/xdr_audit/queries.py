"""Cortex XDR Audit query handlers (read-only)."""
from __future__ import annotations

import random
import time

from repository.xdr_audit_log_repo import xdr_audit_log_repo
from utils.serde import record_dict
from utils.xdr_response import build_xdr_list_reply


def get_management_logs(request_data: dict) -> dict:
    """List management audit logs with optional filtering and pagination.

    Args:
        request_data: The ``request_data`` dict from the POST body.

    Returns:
        XDR list reply with matching audit log entries.
    """
    all_logs = [record_dict(log) for log in xdr_audit_log_repo.list_all()]

    filters = request_data.get("filters", [])
    for f in filters:
        field = f.get("field", "")
        value = f.get("value")
        if field == "sub_type" and value:
            values = value if isinstance(value, list) else [value]
            all_logs = [log for log in all_logs if log["sub_type"] in values]
        elif field == "result" and value:
            values = value if isinstance(value, list) else [value]
            all_logs = [log for log in all_logs if log["result"] in values]
        elif field == "timestamp":
            gte = f.get("gte")
            lte = f.get("lte")
            if gte is not None:
                all_logs = [log for log in all_logs if log["timestamp"] >= gte]
            if lte is not None:
                all_logs = [log for log in all_logs if log["timestamp"] <= lte]

    total = len(all_logs)
    search_from = request_data.get("search_from", 0)
    search_to = request_data.get("search_to", search_from + 100)
    page = all_logs[search_from:search_to]

    return build_xdr_list_reply([_audit_row(log) for log in page], total_count=total)


#: How a stored entry maps onto the row Cortex answers. The route's recorded
#: reply names every field `AUDIT_*`; mockdr answered those keys blank and
#: put the values under the record's own lowercase names beside them, so an
#: XSOAR client reading `AUDIT_DESCRIPTION` — which is what
#: `xdr-get-audit-management-logs` reads — got a page of empty rows with a
#: 200, and the undeclared names carried everything.
_AUDIT_FIELDS = {
    "sub_type": "AUDIT_ENTITY_SUBTYPE",
    "result": "AUDIT_RESULT",
    "timestamp": "AUDIT_INSERT_TIME",
    "user_name": "AUDIT_OWNER_NAME",
    "user_email": "AUDIT_OWNER_EMAIL",
    "description": "AUDIT_DESCRIPTION",
    "host_name": "AUDIT_HOSTNAME",
}


def _audit_row(log: dict) -> dict:
    """One stored entry as the row the route documents."""
    row = {declared: log[stored] for stored, declared in _AUDIT_FIELDS.items() if stored in log}
    # `AUDIT_ID` is a number in the recorded reply; the record is keyed by a
    # string, so the digits of that key are what the row carries.
    digits = "".join(c for c in str(log.get("audit_id", "")) if c.isdigit())
    row["AUDIT_ID"] = int(digits[:12]) if digits else 0
    row["AUDIT_ENTITY"] = "MANAGEMENT"
    return row


def get_agent_reports(request_data: dict) -> dict:
    """Return the agent reports this tenant's endpoints have sent.

    Two failures met here. The rows were canned — `mock-endpoint-001` and
    `ACME-SRV-001`, endpoints `get_endpoint` has never heard of — so a client
    that read a report and looked the endpoint up found nothing. And the
    fields were the record's own lowercase names while the route's recorded
    reply names every one of them `ENDPOINTID`, `ENDPOINTNAME`,
    `TRAPSVERSION` and so on: the documented keys were answered blank beside
    the undeclared ones that carried the values.

    The vocabulary fields the report itself owns — `CATEGORY`, `TYPE`,
    `SUBTYPE`, `RESULT`, `REASON` — are left to the recorded shape's blanks:
    what this install knows is the endpoint, not Cortex's own words for a
    report's kind.

    Args:
        request_data: The ``request_data`` dict from the POST body.

    Returns:
        XDR list reply with one report per endpoint.
    """
    from repository.xdr_endpoint_repo import xdr_endpoint_repo  # noqa: PLC0415

    endpoints = xdr_endpoint_repo.list_all()
    reports = [
        {
            "ENDPOINTID": endpoint.endpoint_id,
            "ENDPOINTNAME": endpoint.endpoint_name,
            "DOMAIN": endpoint.domain,
            "TRAPSVERSION": endpoint.endpoint_version,
            "TIMESTAMP": endpoint.last_seen,
            "RECEIVEDTIME": endpoint.last_seen,
        }
        for endpoint in endpoints
    ]

    search_from = request_data.get("search_from", 0)
    search_to = request_data.get("search_to", search_from + 100)
    return build_xdr_list_reply(
        reports[search_from:search_to], total_count=len(reports),
    )


def _recent_ms() -> int:
    """An epoch-millisecond timestamp within the last day, so a time-bounded client sees it."""
    return int((time.time() - random.uniform(0, 86400)) * 1000)  # noqa: S311
