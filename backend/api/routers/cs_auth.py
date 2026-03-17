"""CrowdStrike OAuth2 token endpoint.

Implements the client credentials flow: clients POST ``client_id`` and
``client_secret`` as form-encoded data and receive a time-limited Bearer
token.

Pre-seeded mock credentials (seeded via ``infrastructure/seeders/cs_oauth.py``):

* Admin:   ``cs-mock-admin-client`` / ``cs-mock-admin-secret``
* Viewer:  ``cs-mock-viewer-client`` / ``cs-mock-viewer-secret``
* Analyst: ``cs-mock-analyst-client`` / ``cs-mock-analyst-secret``
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Form, HTTPException

from repository.cs_oauth_client_repo import cs_oauth_client_repo
from repository.store import store
from utils.cs_response import build_cs_error_response

router = APIRouter(tags=["CrowdStrike Auth"])

_TOKEN_LIFETIME_SECONDS: int = 1799


# ---------------------------------------------------------------------------
# Token endpoint
# ---------------------------------------------------------------------------

@router.post("/oauth2/token")
async def create_token(
    client_id: str = Form(...),
    client_secret: str = Form(...),
) -> dict:
    """Exchange client credentials for an access token.

    Validates against the ``cs_oauth_clients`` repository, generates a
    Bearer token, stores it in ``cs_oauth_tokens`` with expiration, and
    returns the token in CrowdStrike format.

    Args:
        client_id:     OAuth2 client identifier (form-encoded).
        client_secret: OAuth2 client secret (form-encoded).

    Returns:
        Dict with ``access_token``, ``token_type``, and ``expires_in``.

    Raises:
        HTTPException: 401 if the credentials are invalid.
    """
    client = cs_oauth_client_repo.get_by_secret(client_id, client_secret)
    if client is None:
        raise HTTPException(
            status_code=401,
            detail=build_cs_error_response(
                401, "invalid client credentials",
            ),
        )

    access_token = str(uuid.uuid4())
    expires_at = datetime.now(UTC) + timedelta(seconds=_TOKEN_LIFETIME_SECONDS)

    token_record: dict = {
        "access_token": access_token,
        "client_id": client_id,
        "role": client.role,
        "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    }
    store.save("cs_oauth_tokens", access_token, token_record)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": _TOKEN_LIFETIME_SECONDS,
    }
