"""Read-side handlers for Microsoft Graph Identity Protection."""
from __future__ import annotations

from dataclasses import asdict

from repository.graph.risk_detection_repo import graph_risk_detection_repo
from repository.graph.risky_user_repo import graph_risky_user_repo
from utils.graph_odata import apply_graph_filter
from utils.graph_response import build_graph_list_response


def list_risky_users(
    filter_str: str | None = None,
    top: int = 100,
    skip: int = 0,
) -> dict:
    """Return risky users with OData query support.

    Args:
        filter_str: OData ``$filter`` expression.
        top:        Page size (``$top``).
        skip:       Number of records to skip (``$skip``).

    Returns:
        OData list response dict.
    """
    records = [asdict(u) for u in graph_risky_user_repo.list_all()]

    if filter_str:
        records = apply_graph_filter(records, filter_str)

    total = len(records)
    page = records[skip : skip + top]
    next_link = (
        f"https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#identityProtection/riskyUsers",
        next_link=next_link,
    )


def get_risky_user(user_id: str) -> dict | None:
    """Return a single risky user by ID.

    Args:
        user_id: The risky user's ``id``.

    Returns:
        Risky user dict or ``None`` if not found.
    """
    user = graph_risky_user_repo.get(user_id)
    if user is None:
        return None
    return asdict(user)


def list_risk_detections(
    filter_str: str | None = None,
    top: int = 100,
    skip: int = 0,
) -> dict:
    """Return risk detections with OData query support.

    Args:
        filter_str: OData ``$filter`` expression.
        top:        Page size (``$top``).
        skip:       Number of records to skip (``$skip``).

    Returns:
        OData list response dict.
    """
    records = [asdict(d) for d in graph_risk_detection_repo.list_all()]

    if filter_str:
        records = apply_graph_filter(records, filter_str)

    total = len(records)
    page = records[skip : skip + top]
    next_link = (
        f"https://graph.microsoft.com/v1.0/identityProtection/riskDetections?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#identityProtection/riskDetections",
        next_link=next_link,
    )
