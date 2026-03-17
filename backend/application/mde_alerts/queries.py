"""Microsoft Defender for Endpoint Alert query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.mde_alert_repo import mde_alert_repo
from utils.mde_odata import apply_odata_filter, apply_odata_orderby, apply_odata_select
from utils.mde_response import build_mde_list_response


def list_alerts(
    filter_str: str | None,
    top: int,
    skip: int,
    orderby: str | None,
    select: str | None,
) -> dict:
    """List alerts with OData filtering, ordering, selection, and pagination.

    Args:
        filter_str: OData ``$filter`` expression, or None for all alerts.
        top:        Maximum number of records to return (``$top``).
        skip:       Number of records to skip (``$skip``).
        orderby:    OData ``$orderby`` expression, or None.
        select:     Comma-separated field names (``$select``), or None.

    Returns:
        OData list response with paginated alert records.
    """
    records = [asdict(a) for a in mde_alert_repo.list_all()]
    if filter_str:
        records = apply_odata_filter(records, filter_str)
    records = apply_odata_orderby(records, orderby)
    total = len(records)
    page = records[skip : skip + top]
    page = apply_odata_select(page, select)
    next_link = None
    if skip + top < total:
        next_link = (
            f"https://api.securitycenter.microsoft.com/api/alerts"
            f"?$top={top}&$skip={skip + top}"
        )
    return build_mde_list_response(page, next_link=next_link)


def get_alert(alert_id: str) -> dict | None:
    """Get a single alert by its alert ID.

    Args:
        alert_id: The GUID of the alert to retrieve.

    Returns:
        Alert dict, or None if not found.
    """
    alert = mde_alert_repo.get(alert_id)
    if not alert:
        return None
    return asdict(alert)
