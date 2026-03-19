"""Microsoft Graph OAuth2 token endpoint.

Implements the Azure AD client credentials flow: clients POST ``client_id``,
``client_secret``, and ``grant_type=client_credentials`` as form-encoded data
and receive a time-limited Bearer token.

Pre-seeded mock credentials (seeded via ``infrastructure/seeders/graph/graph_oauth.py``):

* Admin:    ``graph-mock-admin-client`` / ``graph-mock-admin-secret``
* Security: ``graph-mock-security-client`` / ``graph-mock-security-secret``
* SMB:      ``graph-mock-smb-client`` / ``graph-mock-smb-secret``
* Plan 1:   ``graph-mock-p1-client`` / ``graph-mock-p1-secret``
* Intune:   ``graph-mock-intune-client`` / ``graph-mock-intune-secret``
* Mail:     ``graph-mock-mail-client`` / ``graph-mock-mail-secret``
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Form, HTTPException

from repository.graph.oauth_client_repo import graph_oauth_client_repo
from repository.store import store
from utils.graph_response import build_graph_error_response

router = APIRouter(tags=["Graph Auth"])

_TOKEN_LIFETIME_SECONDS: int = 3599


@router.post("/oauth2/v2.0/token")
async def create_token(
    client_id: str = Form(...),
    client_secret: str = Form(...),
    grant_type: str = Form(...),
    scope: str = Form("https://graph.microsoft.com/.default"),
) -> dict:
    """Exchange client credentials for an access token.

    Validates the ``grant_type`` is ``client_credentials``, checks the
    credentials against the ``graph_oauth_clients`` repository, generates a
    Bearer token, stores it in ``graph_oauth_tokens`` with expiration, and
    returns the token in Azure AD format.

    Args:
        client_id:     OAuth2 client identifier (form-encoded).
        client_secret: OAuth2 client secret (form-encoded).
        grant_type:    Must be ``"client_credentials"``.
        scope:         OAuth2 scope (ignored — mock accepts any scope).

    Returns:
        Dict with ``access_token``, ``token_type``, ``expires_in``, and
        ``ext_expires_in``.

    Raises:
        HTTPException: 400 if grant_type is invalid.
        HTTPException: 401 if the credentials are invalid.
    """
    if grant_type != "client_credentials":
        raise HTTPException(
            status_code=400,
            detail=build_graph_error_response(
                "invalid_grant",
                "Unsupported grant_type. Only client_credentials is supported.",
            ),
        )

    client = graph_oauth_client_repo.get(client_id)
    if client is None or client.client_secret != client_secret:
        raise HTTPException(
            status_code=401,
            detail=build_graph_error_response(
                "invalid_client", "Invalid client credentials",
            ),
        )

    access_token = str(uuid.uuid4())
    expires_at = datetime.now(UTC) + timedelta(seconds=_TOKEN_LIFETIME_SECONDS)

    token_record: dict = {
        "access_token": access_token,
        "client_id": client_id,
        "tenant_id": client.tenant_id,
        "role": client.role,
        "plan": client.plan,
        "licenses": client.licenses,
        "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    }
    store.save("graph_oauth_tokens", access_token, token_record)

    return {
        "token_type": "Bearer",
        "expires_in": _TOKEN_LIFETIME_SECONDS,
        "ext_expires_in": _TOKEN_LIFETIME_SECONDS,
        "access_token": access_token,
    }
