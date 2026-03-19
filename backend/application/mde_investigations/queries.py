"""Microsoft Defender for Endpoint Investigation query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.mde_investigation_repo import mde_investigation_repo
from utils.mde_odata import apply_odata_filter, apply_odata_orderby
from utils.mde_response import build_mde_list_response


def list_investigations(
    filter_str: str | None,
    top: int,
    skip: int,
    orderby: str | None,
) -> dict:
    """List investigations with OData filtering, ordering, and pagination.

    Args:
        filter_str: OData ``$filter`` expression, or None for all investigations.
        top:        Maximum number of records to return (``$top``).
        skip:       Number of records to skip (``$skip``).
        orderby:    OData ``$orderby`` expression, or None.

    Returns:
        OData list response with paginated investigation records.
    """
    records = [asdict(inv) for inv in mde_investigation_repo.list_all()]
    if filter_str:
        records = apply_odata_filter(records, filter_str)
    records = apply_odata_orderby(records, orderby)
    total = len(records)
    page = records[skip : skip + top]
    next_link = None
    if skip + top < total:
        next_link = (
            f"https://api.securitycenter.microsoft.com/api/investigations"
            f"?$top={top}&$skip={skip + top}"
        )
    return build_mde_list_response(page, next_link=next_link)


def get_investigation(investigation_id: str) -> dict | None:
    """Get a single investigation by its investigation ID.

    Args:
        investigation_id: The GUID of the investigation to retrieve.

    Returns:
        Investigation dict, or None if not found.
    """
    investigation = mde_investigation_repo.get(investigation_id)
    if not investigation:
        return None
    return asdict(investigation)
