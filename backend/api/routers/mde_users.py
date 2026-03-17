"""Microsoft Defender for Endpoint Users API router.

Implements MDE user-centric endpoints: machines where a user has
logged on, and alerts for those machines.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from api.mde_auth import require_mde_auth
from application.mde_users import queries as user_queries

router = APIRouter(tags=["MDE Users"])


@router.get("/api/users/{user_id}/machines")
def get_user_machines(
    user_id: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get machines where a specific user has logged on."""
    return user_queries.get_user_machines(user_id)


@router.get("/api/users/{user_id}/alerts")
def get_user_alerts(
    user_id: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get alerts for machines where a specific user has logged on."""
    return user_queries.get_user_alerts(user_id)
