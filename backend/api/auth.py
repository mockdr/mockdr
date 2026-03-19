"""FastAPI dependency for ApiToken bearer authentication and RBAC.

Three predefined roles with decreasing privilege:

* **Admin** — full read/write access to all endpoints including user management
  and dev tooling.
* **SOC Analyst** — read access everywhere; write access to threat/alert triage
  endpoints and agent actions.  Cannot manage users, sites, groups, policies,
  firewall rules, device-control rules, exclusions, blocklist, IOCs, or webhooks.
* **Viewer** — read-only access.  All mutations return 403.
"""
from __future__ import annotations

from typing import Any

from fastapi import Depends, Header, HTTPException

from repository.user_repo import user_repo
from utils.token_expiry import is_token_expired

_UNAUTH: dict[str, Any] = {
    "errors": [{"code": 4010010, "detail": "Token is invalid", "title": "Unauthorized"}],
    "data": None,
}

_EXPIRED: dict[str, Any] = {
    "errors": [{"code": 4010011, "detail": "Token has expired", "title": "Unauthorized"}],
    "data": None,
}

_FORBIDDEN: dict[str, Any] = {
    "errors": [{"code": 4030010, "detail": "Insufficient permissions", "title": "Forbidden"}],
    "data": None,
}

# ── Role hierarchy ────────────────────────────────────────────────────────────
# Roles that are allowed to perform *write* operations on the listed domains.
# Everything not listed here is read-only for the given role.

_WRITE_ROLES: frozenset[str] = frozenset({"Admin", "SOC Analyst"})
_ADMIN_ROLES: frozenset[str] = frozenset({"Admin"})


async def require_auth(authorization: str = Header(None)) -> dict:
    """Validate the ApiToken bearer header and return the token record.

    Raises:
        HTTPException: 401 if the token is missing, malformed, unknown, or expired.
    """
    if not authorization or not authorization.startswith("ApiToken "):
        raise HTTPException(status_code=401, detail=_UNAUTH)
    token = authorization[len("ApiToken "):]
    record = user_repo.get_token_record(token)
    if not record:
        raise HTTPException(status_code=401, detail=_UNAUTH)
    if is_token_expired(record):
        raise HTTPException(status_code=401, detail=_EXPIRED)
    return record


async def require_write(current_user: dict = Depends(require_auth)) -> dict:
    """Require at least SOC Analyst role (Admin or SOC Analyst).

    Use this for threat/alert triage and agent action endpoints.
    """
    if current_user.get("role") not in _WRITE_ROLES:
        raise HTTPException(status_code=403, detail=_FORBIDDEN)
    return current_user


async def require_admin(current_user: dict = Depends(require_auth)) -> dict:
    """Require Admin role.

    Use this for user management, site/group/policy CRUD, firewall, device
    control, exclusions, blocklist, IOC, webhook, and dev endpoints.
    """
    if current_user.get("role") not in _ADMIN_ROLES:
        raise HTTPException(status_code=403, detail=_FORBIDDEN)
    return current_user
