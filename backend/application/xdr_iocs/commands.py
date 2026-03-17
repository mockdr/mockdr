"""Cortex XDR IOC command handlers (mutations)."""
from __future__ import annotations

import uuid

from domain.xdr_ioc import XdrIoc
from repository.xdr_ioc_repo import xdr_ioc_repo
from utils.xdr_response import build_xdr_reply


def insert_iocs(iocs: list[dict]) -> dict:
    """Batch insert IOC indicators.

    Args:
        iocs: List of IOC dicts to insert.

    Returns:
        XDR reply confirming success.
    """
    for ioc_data in iocs:
        ioc_id = ioc_data.get("ioc_id", str(uuid.uuid4()))
        ioc = XdrIoc(
            ioc_id=ioc_id,
            indicator=ioc_data.get("indicator", ""),
            type=ioc_data.get("type", "hash"),
            severity=ioc_data.get("severity", "medium"),
            reputation=ioc_data.get("reputation", "unknown"),
            status=ioc_data.get("status", "enabled"),
            expiration_date=ioc_data.get("expiration_date"),
            comment=ioc_data.get("comment", ""),
            vendors=ioc_data.get("vendors", []),
        )
        xdr_ioc_repo.save(ioc)

    return build_xdr_reply(True)


def enable_iocs(ioc_ids: list[str]) -> dict:
    """Enable one or more IOCs.

    Args:
        ioc_ids: List of IOC identifiers to enable.

    Returns:
        XDR reply confirming success.
    """
    for ioc_id in ioc_ids:
        ioc = xdr_ioc_repo.get(ioc_id)
        if ioc:
            ioc.status = "enabled"
            xdr_ioc_repo.save(ioc)

    return build_xdr_reply(True)


def disable_iocs(ioc_ids: list[str]) -> dict:
    """Disable one or more IOCs.

    Args:
        ioc_ids: List of IOC identifiers to disable.

    Returns:
        XDR reply confirming success.
    """
    for ioc_id in ioc_ids:
        ioc = xdr_ioc_repo.get(ioc_id)
        if ioc:
            ioc.status = "disabled"
            xdr_ioc_repo.save(ioc)

    return build_xdr_reply(True)
