"""Read-side handlers for Microsoft Graph Subscribed SKUs (Licenses)."""
from __future__ import annotations

from dataclasses import asdict

from repository.graph.subscribed_sku_repo import graph_subscribed_sku_repo
from utils.graph_response import build_graph_list_response


def list_subscribed_skus() -> dict:
    """Return all subscribed SKUs as an OData list.

    Subscribed SKUs are always a small set so no filtering/pagination is needed.

    Returns:
        OData list response containing subscribed SKU records.
    """
    records = [asdict(sku) for sku in graph_subscribed_sku_repo.list_all()]
    return build_graph_list_response(
        value=records,
        context="https://graph.microsoft.com/v1.0/$metadata#subscribedSkus",
    )
