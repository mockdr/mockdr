"""Read-side handlers for Microsoft Graph Subscribed SKUs (Licenses)."""
from __future__ import annotations

from repository.graph.subscribed_sku_repo import graph_subscribed_sku_repo
from repository.graph.user_repo import graph_user_repo
from utils.graph_response import build_graph_list_response, graph_page
from utils.serde import record_dict


def list_subscribed_skus(top: int = 100, skip: int = 0) -> dict:
    """Return all subscribed SKUs as an OData list.

    Subscribed SKUs are always a small set so no filtering/pagination is needed.

    Returns:
        OData list response containing subscribed SKU records.
    """
    holders = _licence_holders()
    records = []
    for sku in graph_subscribed_sku_repo.list_all():
        record = record_dict(sku)
        # consumedUnits was a hardcoded number the seeder chose independently
        # of who actually holds a licence, so every SKU contradicted the user
        # list — two of them reporting more seats consumed than exist. Deriving
        # it here means the two can no longer disagree.
        record["consumedUnits"] = holders.get(record.get("skuId", ""), 0)
        record["prepaidUnits"] = _prepaid_for(record)
        records.append(record)

    page, next_link = graph_page(records, top, skip, resource="subscribedSkus")
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#subscribedSkus",
        next_link=next_link,
    )


def _licence_holders() -> dict[str, int]:
    """Count the users holding each SKU."""
    counts: dict[str, int] = {}
    for user in graph_user_repo.list_all():
        for licence in getattr(user, "assignedLicenses", None) or []:
            sku_id = str(licence.get("skuId", ""))
            if sku_id:
                counts[sku_id] = counts.get(sku_id, 0) + 1
    return counts


def _prepaid_for(record: dict) -> dict:
    """Ensure the subscription has at least as many seats as it has consumed."""
    prepaid = dict(record.get("prepaidUnits") or {})
    enabled = int(prepaid.get("enabled", 0))
    consumed = int(record.get("consumedUnits", 0))
    # A tenant cannot consume more seats than it bought; the seeded numbers
    # described two impossible subscriptions.
    prepaid["enabled"] = max(enabled, consumed)
    return prepaid
