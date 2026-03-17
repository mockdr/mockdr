"""Microsoft Defender for Endpoint Indicator query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.mde_indicator_repo import mde_indicator_repo
from utils.mde_odata import apply_odata_filter, apply_odata_orderby, apply_odata_select
from utils.mde_response import build_mde_list_response


def list_indicators(
    filter_str: str | None,
    top: int,
    skip: int,
    orderby: str | None,
    select: str | None,
) -> dict:
    """List indicators with OData filtering, ordering, selection, and pagination.

    Args:
        filter_str: OData ``$filter`` expression, or None for all indicators.
        top:        Maximum number of records to return (``$top``).
        skip:       Number of records to skip (``$skip``).
        orderby:    OData ``$orderby`` expression, or None.
        select:     Comma-separated field names (``$select``), or None.

    Returns:
        OData list response with paginated indicator records.
    """
    records = [asdict(ind) for ind in mde_indicator_repo.list_all()]
    if filter_str:
        records = apply_odata_filter(records, filter_str)
    records = apply_odata_orderby(records, orderby)
    total = len(records)
    page = records[skip : skip + top]
    page = apply_odata_select(page, select)
    next_link = None
    if skip + top < total:
        next_link = (
            f"https://api.securitycenter.microsoft.com/api/indicators"
            f"?$top={top}&$skip={skip + top}"
        )
    return build_mde_list_response(page, next_link=next_link)


def get_indicator(indicator_id: str) -> dict | None:
    """Get a single indicator by its indicator ID.

    Args:
        indicator_id: The GUID of the indicator to retrieve.

    Returns:
        Indicator dict, or None if not found.
    """
    indicator = mde_indicator_repo.get(indicator_id)
    if not indicator:
        return None
    return asdict(indicator)
