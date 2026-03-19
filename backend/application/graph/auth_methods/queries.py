"""Read-side handlers for Microsoft Graph Authentication Methods."""
from __future__ import annotations

from dataclasses import asdict

from repository.graph.user_registration_detail_repo import (
    graph_user_registration_detail_repo,
)
from utils.graph_odata import apply_graph_filter, apply_odata_orderby
from utils.graph_response import build_graph_list_response


def list_registration_details(
    filter_str: str | None = None,
    top: int = 100,
    skip: int = 0,
) -> dict:
    """Return user registration details with OData query support.

    Args:
        filter_str: OData ``$filter`` expression.
        top:        Page size (``$top``).
        skip:       Number of records to skip (``$skip``).

    Returns:
        OData list response dict.
    """
    records = [asdict(d) for d in graph_user_registration_detail_repo.list_all()]

    if filter_str:
        records = apply_graph_filter(records, filter_str)

    records = apply_odata_orderby(records, None)
    total = len(records)
    page = records[skip : skip + top]
    next_link = (
        "https://graph.microsoft.com/v1.0/reports/"
        "authenticationMethods/"
        f"userRegistrationDetails?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#reports/authenticationMethods/userRegistrationDetails",
        next_link=next_link,
    )
