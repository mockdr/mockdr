"""Cortex XDR IOC query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.xdr_ioc_repo import xdr_ioc_repo
from utils.xdr_response import build_xdr_list_reply


def get_iocs(request_data: dict) -> dict:
    """List IOCs with optional filtering and pagination.

    Args:
        request_data: The ``request_data`` dict from the POST body.

    Returns:
        XDR list reply with matching IOCs.
    """
    all_iocs = [asdict(i) for i in xdr_ioc_repo.list_all()]

    ioc_type = request_data.get("type")
    if ioc_type:
        values = ioc_type if isinstance(ioc_type, list) else [ioc_type]
        all_iocs = [i for i in all_iocs if i["type"] in values]

    status = request_data.get("status")
    if status:
        values = status if isinstance(status, list) else [status]
        all_iocs = [i for i in all_iocs if i["status"] in values]

    total = len(all_iocs)
    search_from = request_data.get("search_from", 0)
    search_to = request_data.get("search_to", search_from + 100)
    page = all_iocs[search_from:search_to]

    return build_xdr_list_reply(page, total_count=total, key="iocs")
