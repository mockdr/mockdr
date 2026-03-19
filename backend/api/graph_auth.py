"""FastAPI dependencies for Microsoft Graph OAuth2 Bearer authentication.

Graph uses Azure AD OAuth2 client credentials flow.  Clients POST to
``/graph/oauth2/v2.0/token`` with ``client_id``, ``client_secret``, and
``grant_type=client_credentials`` to receive a time-limited Bearer token.

Each token carries ``plan`` and ``licenses`` attributes used for feature gating.

Predefined roles:

* **owner** — full read/write access.
* **contributor** — read + write for most endpoints.
* **reader** — read-only access.  All mutations return 403.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from fastapi import Depends, Header, HTTPException

from repository.store import store
from utils.graph_response import build_graph_error_response
from utils.token_expiry import is_token_expired

# ── Role sets ────────────────────────────────────────────────────────────────

_WRITE_ROLES: frozenset[str] = frozenset({"owner", "contributor"})

# ── Feature gating ───────────────────────────────────────────────────────────

FEATURE_GATES: dict[str, set[str] | str] = {
    # Security (Plan 2 or Defender for Business)
    "security/alerts_v2": {"plan2", "defender_for_business"},
    "security/incidents": {"plan2", "defender_for_business"},
    "security/secureScores": {"plan2"},
    "security/runHuntingQuery": {"plan2"},
    "security/tiIndicators": {"plan2"},
    # Identity Protection (Entra P2 — Plan 2 or E5)
    "identityProtection": {"plan2"},
    # Audit logs (Entra P1+ — Plan 2, E5, or E3)
    "auditLogs/signIns": {"plan2", "defender_for_business"},
    "auditLogs/directoryAudits": "any",
    # Intune (requires Intune or Plan 2 or DfB)
    "deviceManagement": {"plan2", "defender_for_business"},
    # Defender for Office 365
    "attackSimulation": {"plan2"},
    # Always available
    "users": "any",
    "groups": "any",
    "organization": "any",
    "directoryRoles": "any",
    "conditionalAccess": "any",
    "servicePrincipals": "any",
    "mail": "any",
    "drives": "any",
    "teams": "any",
    "subscribedSkus": "any",
    "applications": "any",
    "reports": "any",
    "directory": "any",
    "serviceAnnouncement": "any",
}

# ── Public dependencies ──────────────────────────────────────────────────────


async def require_graph_auth(authorization: str = Header(None)) -> dict:
    """Validate Graph Bearer token and return the token record.

    Extracts the token from the ``Authorization: Bearer <token>`` header,
    looks it up in the ``graph_oauth_tokens`` collection, and verifies it has
    not expired.

    Args:
        authorization: Raw ``Authorization`` header value.

    Returns:
        The stored token record dict (includes ``client_id``, ``role``,
        ``plan``, ``licenses``, etc.).

    Raises:
        HTTPException: 401 if the token is missing, malformed, or unknown.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail=build_graph_error_response(
                "InvalidAuthenticationToken",
                "Access token is missing or malformed",
            ),
        )

    token = authorization[7:]
    record = store.get("graph_oauth_tokens", token)
    if not record:
        raise HTTPException(
            status_code=401,
            detail=build_graph_error_response(
                "InvalidAuthenticationToken",
                "Access token is invalid or expired",
            ),
        )

    if is_token_expired(record, key="expires_at"):
        raise HTTPException(
            status_code=401,
            detail=build_graph_error_response(
                "InvalidAuthenticationToken",
                "Access token has expired",
            ),
        )

    return cast(dict[str, Any], record)


async def require_graph_write(
    current_client: dict = Depends(require_graph_auth),  # noqa: B008
) -> dict:
    """Require owner or contributor role for write operations.

    Args:
        current_client: Injected by ``require_graph_auth``.

    Returns:
        The authenticated client record.

    Raises:
        HTTPException: 403 if the client role is not permitted to write.
    """
    if current_client.get("role") not in _WRITE_ROLES:
        raise HTTPException(
            status_code=403,
            detail=build_graph_error_response(
                "Authorization_RequestDenied",
                "Insufficient privileges to complete the operation.",
            ),
        )
    return current_client


def require_graph_feature(feature: str) -> Callable:
    """Dependency factory for plan-based feature gating.

    Usage::

        @router.get("/v1.0/security/alerts_v2")
        async def list_alerts(
            _: dict = Depends(require_graph_feature("security/alerts_v2")),
        ):
            ...

    Args:
        feature: Feature key from :data:`FEATURE_GATES`.

    Returns:
        A FastAPI dependency that validates the token's plan against the
        feature gate.
    """
    async def _check(
        current_client: dict = Depends(require_graph_auth),  # noqa: B008
    ) -> dict:
        gate = FEATURE_GATES.get(feature, "any")
        if gate == "any":
            return current_client

        plan = current_client.get("plan", "none")
        if isinstance(gate, set) and plan not in gate:
            raise HTTPException(
                status_code=403,
                detail=build_graph_error_response(
                    "Authorization_RequestDenied",
                    f"This feature requires a higher license tier. "
                    f"Current plan: {plan}. Required: {', '.join(sorted(gate))}.",
                ),
            )
        return current_client

    return _check
