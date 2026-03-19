"""Microsoft Graph Subscribed SKUs (Licenses) endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from api.graph_auth import require_graph_auth
from application.graph.licenses import queries as license_queries

router = APIRouter(tags=["Graph Licenses"])


@router.get("/v1.0/subscribedSkus")
async def list_subscribed_skus(
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List all subscribed SKUs (licences)."""
    return license_queries.list_subscribed_skus()
