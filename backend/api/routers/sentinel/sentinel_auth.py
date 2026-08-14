"""Sentinel OAuth2 authentication router."""
from __future__ import annotations

from fastapi import APIRouter, Form, HTTPException

from application.sentinel.commands.auth import client_tenant, token_exchange
from utils.entra_tenant import tenant_rejection_message, tenant_segment_matches
from utils.entra_token_errors import (
    AADSTS_INVALID_CLIENT,
    AADSTS_TENANT_NOT_FOUND,
    build_token_error,
)

router = APIRouter(tags=["Sentinel Auth"])


@router.post("/oauth2/v2.0/token")
async def oauth2_token(
    client_id: str = Form(default=""),
    client_secret: str = Form(default=""),
    grant_type: str = Form(default=""),
) -> dict:
    """Exchange client credentials for an access token."""
    return _issue_token(None, client_id, client_secret)


@router.post("/{tenant_id}/oauth2/v2.0/token")
async def oauth2_token_for_tenant(
    tenant_id: str,
    client_id: str = Form(default=""),
    client_secret: str = Form(default=""),
    grant_type: str = Form(default=""),
) -> dict:
    """Exchange client credentials on the tenant-scoped URL real Entra uses.

    Args:
        tenant_id:     Tenant GUID or verified domain name from the URL. Must
                       address the credential's tenant unless
                       ``MOCKDR_STRICT_TENANT=false``.
        client_id:     Azure AD application client ID (form-encoded).
        client_secret: Client secret (form-encoded).
        grant_type:    Must be ``"client_credentials"``.

    Returns:
        Token response — see :func:`_issue_token`.
    """
    return _issue_token(tenant_id, client_id, client_secret)


def _issue_token(tenant_id: str | None, client_id: str, client_secret: str) -> dict:
    """Resolve the tenant, validate the credentials and mint a token.

    Args:
        tenant_id:     Tenant from the URL, or ``None`` on the bare path.
        client_id:     Azure AD application client ID.
        client_secret: Client secret.

    Returns:
        Token response dict.

    Raises:
        HTTPException: 400 if the tenant does not address this directory.
        HTTPException: 401 if the credentials are invalid.
    """
    if not tenant_segment_matches(tenant_id, *client_tenant(client_id)):
        raise HTTPException(status_code=400, detail=build_token_error(
            "invalid_request",
            tenant_rejection_message(tenant_id),
            AADSTS_TENANT_NOT_FOUND,
        ))

    result = token_exchange(client_id, client_secret)
    if not result:
        raise HTTPException(status_code=401, detail=build_token_error(
            "invalid_client",
            "AADSTS7000215: Invalid client secret provided.",
            AADSTS_INVALID_CLIENT,
        ))
    return result
