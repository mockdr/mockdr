"""Elastic Security token endpoint.

Implements an optional Bearer token exchange (grant_type=password) similar
to the CrowdStrike/MDE pattern but adapted for Elastic.

Pre-seeded mock credentials:

* Admin:   ``elastic`` / ``mock-elastic-password``
* Analyst: ``analyst`` / ``mock-analyst-password``
* Viewer:  ``viewer`` / ``mock-viewer-password``
"""
from __future__ import annotations

import hmac
import uuid

from fastapi import APIRouter, HTTPException

from api.es_auth import _USERS
from repository.store import store
from utils.dt import utc_now
from utils.es_response import build_es_error_response

router = APIRouter(tags=["Elastic Security Auth"])

_TOKEN_LIFETIME_SECONDS: int = 3600


# ---------------------------------------------------------------------------
# Token endpoint
# ---------------------------------------------------------------------------

@router.post("/_security/oauth2/token")
async def create_token(body: dict) -> dict:
    """Exchange username/password for an access token.

    Accepts a JSON body with ``grant_type``, ``username``, and ``password``.

    Args:
        body: Request body with credentials.

    Returns:
        Dict with ``access_token``, ``type``, and ``expires_in``.

    Raises:
        HTTPException: 401 if the credentials are invalid.
    """
    username = body.get("username", "")
    password = body.get("password", "")

    user = _USERS.get(username)
    if user is None or not hmac.compare_digest(user["password"], password):
        raise HTTPException(
            status_code=401,
            detail=build_es_error_response(
                401, "security_exception",
                "unable to authenticate user [" + username + "]",
            ),
        )

    access_token = str(uuid.uuid4())

    # Store the token so it can be validated by require_es_auth
    store.save("es_api_keys", access_token, {
        "id": access_token,
        "api_key": access_token,
        "role": user["role"],
        "name": f"token-{username}",
        "created_at": utc_now(),
    })

    return {
        "access_token": access_token,
        "type": "Bearer",
        "expires_in": _TOKEN_LIFETIME_SECONDS,
    }
