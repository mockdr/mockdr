"""Cortex XDR Audit query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.xdr_audit_log_repo import xdr_audit_log_repo
from utils.xdr_response import build_xdr_list_reply


def get_management_logs(request_data: dict) -> dict:
    """List management audit logs with optional filtering and pagination.

    Args:
        request_data: The ``request_data`` dict from the POST body.

    Returns:
        XDR list reply with matching audit log entries.
    """
    all_logs = [asdict(log) for log in xdr_audit_log_repo.list_all()]

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

    return build_xdr_list_reply(page, total_count=total)


def get_agent_reports(request_data: dict) -> dict:
    """Return synthetic agent reports.

    Args:
        request_data: The ``request_data`` dict from the POST body.

    Returns:
        XDR reply with canned agent report data.
    """
    reports = [
        {
            "endpoint_id": "mock-endpoint-001",
            "endpoint_name": "ACME-WS-001",
            "report_type": "agent_status",
            "status": "connected",
            "content_version": "390-101234",
            "agent_version": "8.3.0.12345",
            "os_type": "windows",
            "last_report_time": 1700000000000,
        },
        {
            "endpoint_id": "mock-endpoint-002",
            "endpoint_name": "ACME-SRV-001",
            "report_type": "agent_status",
            "status": "connected",
            "content_version": "390-101234",
            "agent_version": "8.3.0.12345",
            "os_type": "linux",
            "last_report_time": 1700000000000,
        },
    ]

    return build_xdr_list_reply(reports, total_count=len(reports))
