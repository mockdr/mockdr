"""Sentinel OAuth2 authentication router."""
from __future__ import annotations

from fastapi import APIRouter, Form, HTTPException

from application.sentinel.commands.auth import token_exchange
from utils.entra_tenant import tenant_not_found_message, tenant_segment_matches

router = APIRouter(tags=["Sentinel Auth"])


@router.post("/{tenant_id}/oauth2/v2.0/token")
@router.post("/oauth2/v2.0/token")
async def oauth2_token(
    tenant_id: str | None = None,
    client_id: str = Form(default=""),
    client_secret: str = Form(default=""),
    grant_type: str = Form(default=""),
) -> dict:
    """Exchange client credentials for an access token.

    Accepts both the bare path and the tenant-scoped
    ``/{tenant_id}/oauth2/v2.0/token`` path real Entra uses. Sentinel's mock
    credentials carry no tenant, so any concrete tenant is accepted — only the
    multi-tenant aliases Entra rejects for client credentials are refused.
    """
    if not tenant_segment_matches(tenant_id):
        raise HTTPException(status_code=400, detail={
            "error": "invalid_request",
            "error_description": tenant_not_found_message(tenant_id),
        })

    result = token_exchange(client_id, client_secret)
    if not result:
        raise HTTPException(status_code=401, detail={
            "error": "invalid_client",
            "error_description": "Invalid client credentials",
        })
    return result
