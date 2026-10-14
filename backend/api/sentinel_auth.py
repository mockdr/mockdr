"""FastAPI dependencies for Microsoft Sentinel Azure AD OAuth2 authentication.

Sentinel uses Azure AD client credentials grant:
1. POST ``/sentinel/oauth2/v2.0/token`` with ``client_id`` + ``client_secret``
   → returns ``access_token``
2. All subsequent requests: ``Authorization: Bearer <token>``

Pre-seeded credentials:
- Client ID: ``sentinel-mock-client-id``
- Client Secret: ``sentinel-mock-client-secret``
"""
from __future__ import annotations

import re
import secrets
import time
from datetime import date
from typing import cast

from fastapi import Header, HTTPException, Query
from starlette.requests import Request

from repository.store import store
from utils.bearer_challenge import bearer_challenge
from utils.sentinel.response import build_arm_error

_SENTINEL_TOKEN_COLLECTION = "sentinel_oauth_tokens"
_TOKEN_TTL = 3600  # 1 hour


#: The audiences Azure Resource Manager accepts, as its refusal lists them.
ARM_AUDIENCES = (
    "https://management.core.windows.net/",
    "https://management.core.windows.net",
    "https://management.azure.com/",
    "https://management.azure.com",
)

#: The audiences the Logs query API (api.loganalytics.io) accepts.
LOG_ANALYTICS_AUDIENCES = (
    "https://api.loganalytics.io",
    "https://api.loganalytics.io/",
    "https://api.loganalytics.azure.com",
    "https://api.loganalytics.azure.com/",
)


def audience_of(scope: str) -> str:
    """The resource a client-credentials `scope` asks a token for.

    A v2 scope names the resource and a permission —
    `https://management.azure.com/.default` — and the token's `aud` is the
    resource. With several scopes the first names the resource, as Entra
    issues one token per resource.
    """
    first = (scope or "").split()[0] if (scope or "").split() else ""
    for suffix in ("/.default", "/user_impersonation"):
        if first.endswith(suffix):
            resource = first[: -len(suffix)]
            # ARM's audiences carry the trailing slash; Log Analytics' do not.
            return resource + "/" if resource.startswith("https://management.") else resource
    return first


def create_sentinel_token(
    client_id: str, scope: str = "https://management.azure.com/.default",
) -> dict:
    """Create a new OAuth2 access token for the given client.

    The members Entra's v2 endpoint answers with, and no more: `resource`
    belongs to the v1.0 endpoint this mount is not, and the two other Entra
    mounts in this mock — Defender and Graph, the same directory — have
    never sent it.

    The token remembers the resource its `scope` asked for. A token is
    issued for one audience, and each API accepts only its own: Azure
    Resource Manager refuses a Log Analytics token, and Log Analytics an
    ARM one. The mock accepted any token anywhere, so a client that asked
    for the wrong scope passed here and failed against Azure.

    Args:
        client_id: The authenticated client ID.
        scope:     The scope the token request named.

    Returns:
        Token response dict with ``access_token``, ``token_type``,
        ``expires_in`` and ``ext_expires_in``.
    """
    access_token = secrets.token_hex(32)
    store.save(_SENTINEL_TOKEN_COLLECTION, access_token, {
        "client_id": client_id,
        "created_at": time.time(),
        "audience": audience_of(scope),
    })
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": _TOKEN_TTL,
        "ext_expires_in": _TOKEN_TTL,
    }


def _resolve_token(token: str) -> dict | None:
    """Return the record of a valid token — client and audience — or None."""
    record = store.get(_SENTINEL_TOKEN_COLLECTION, token)
    if not record:
        return None
    created_at = record.get("created_at", 0)
    if time.time() - created_at > _TOKEN_TTL:
        store.delete(_SENTINEL_TOKEN_COLLECTION, token)
        return None
    return cast(dict, record)


#: Where this mount issues the tokens it asks for.
_TOKEN_PATH = "/sentinel/oauth2/v2.0/token"


def _bearer_record(request: Request, authorization: str | None) -> dict:
    """The record of the request's bearer token, or a 401 refusal."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail=build_arm_error("AuthenticationFailed", "Bearer token required"),
            headers=bearer_challenge(request, _TOKEN_PATH),
        )

    token = authorization[7:]
    record = _resolve_token(token)
    if not record:
        raise HTTPException(
            status_code=401,
            detail=build_arm_error("AuthenticationFailed", "Invalid or expired token"),
            headers=bearer_challenge(
                request, _TOKEN_PATH, "Invalid or expired token"),
        )
    return record


def _audience_message(audience: str, allowed: tuple[str, ...]) -> str:
    """Azure's own wording for a token issued to someone else."""
    listed = ",".join(f"'{a}'" for a in allowed)
    return (
        f"The access token has been obtained for wrong audience or resource "
        f"'{audience}'. It should exactly match with one of the allowed "
        f"audiences {listed}."
    )


async def require_sentinel_auth(
    request: Request,
    authorization: str | None = Header(None),
) -> dict:
    """Validate an Azure Resource Manager bearer token and return client info.

    A token issued for another resource — Log Analytics, Graph — is refused
    the way ARM refuses it: 401 `InvalidAuthenticationTokenAudience`, naming
    the audience the token has and the ones ARM takes.

    Args:
        request:       The refused request, for the challenge's own URL.
        authorization: The Authorization header value.

    Returns:
        Dict with ``client_id`` key.

    Raises:
        HTTPException: 401 if the token is missing, invalid, or not for ARM.
    """
    record = _bearer_record(request, authorization)
    audience = str(record.get("audience", ""))
    if audience not in ARM_AUDIENCES:
        raise HTTPException(
            status_code=401,
            detail=build_arm_error(
                "InvalidAuthenticationTokenAudience",
                _audience_message(audience, ARM_AUDIENCES),
            ),
            headers=bearer_challenge(request, _TOKEN_PATH, "Invalid audience"),
        )
    return {"client_id": record["client_id"]}


async def require_log_analytics_auth(
    request: Request,
    authorization: str | None = Header(None),
) -> dict:
    """Validate a Logs query API bearer token and return client info.

    The Logs query API takes tokens for `https://api.loganalytics.io`; one
    issued for ARM is refused with `InvalidAuthenticationTokenAudience`,
    which the Azure Monitor "Logs query timeouts and errors" page lists as a
    403.

    Raises:
        HTTPException: 401 if the token is missing or invalid, 403 if it is
            for another resource.
    """
    record = _bearer_record(request, authorization)
    audience = str(record.get("audience", ""))
    if audience not in LOG_ANALYTICS_AUDIENCES:
        raise HTTPException(
            status_code=403,
            detail=build_arm_error(
                "InvalidAuthenticationTokenAudience",
                _audience_message(audience, LOG_ANALYTICS_AUDIENCES[::2]),
            ),
        )
    return {"client_id": record["client_id"]}


# ── ARM api-version enforcement ──────────────────────────────────────────────

_API_VERSION_PATTERN = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(-preview)?$")

EARLIEST_API_VERSION = date(2019, 1, 1)
"""Floor for a plausible SecurityInsights api-version.

Pinning an exact allow-list would go stale every time Azure ships a preview, so
the mock instead accepts any well-formed date from the era in which the
Microsoft.SecurityInsights provider has existed. That still rejects what
clients actually get wrong: a missing parameter, a truncated date, or a
placeholder like ``v1``.
"""


async def require_arm_api_version(
    api_version: str | None = Query(default=None, alias="api-version"),
) -> str:
    """Require a supported ``api-version`` on ARM management-plane requests.

    Azure Resource Manager rejects any management request without an
    ``api-version`` query parameter, and rejects versions it does not serve.
    Accepting the request regardless — as a mock easily does by giving the
    parameter a default — hides a client bug that would surface immediately
    against real Azure.

    Args:
        api_version: Value of the ``api-version`` query parameter.

    Returns:
        The validated API version.

    Raises:
        HTTPException: 400 if the parameter is missing or unsupported.
    """
    if not api_version:
        raise HTTPException(
            status_code=400,
            detail=build_arm_error(
                "MissingApiVersionParameter",
                "The api-version query parameter (?api-version=) is required "
                "for all requests.",
            ),
        )

    if not _is_plausible_api_version(api_version):
        raise HTTPException(
            status_code=400,
            detail=build_arm_error(
                "InvalidApiVersionParameter",
                f"The api-version '{api_version}' is invalid. Expected a "
                f"Microsoft.SecurityInsights version such as '2024-03-01'.",
            ),
        )

    return api_version


def _is_plausible_api_version(api_version: str) -> bool:
    """Report whether a value could be a SecurityInsights api-version.

    Args:
        api_version: Raw ``api-version`` query parameter value.

    Returns:
        True if it is a well-formed date, optionally ``-preview``, no earlier
        than :data:`EARLIEST_API_VERSION`.
    """
    match = _API_VERSION_PATTERN.match(api_version)
    if not match:
        return False
    try:
        released = date(int(match[1]), int(match[2]), int(match[3]))
    except ValueError:
        return False
    return released >= EARLIEST_API_VERSION
