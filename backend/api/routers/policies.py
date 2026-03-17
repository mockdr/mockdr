from fastapi import APIRouter, Depends, Query

from api.auth import require_admin
from api.dto.requests import PolicyUpdateBody
from application.policies import commands as policy_commands
from application.policies import queries as policy_queries

router = APIRouter(tags=["Policies"])


@router.get("/policies")
def get_policy(
    siteId: str = Query(None),
    groupId: str = Query(None),
) -> dict:
    """Return the policy for the specified site or group."""
    result = policy_queries.get_policy(siteId, groupId)
    return result or {"data": None}


@router.put("/policies")
def update_policy(
    body: PolicyUpdateBody,
    siteId: str = Query(None),
    groupId: str = Query(None),
    current_user: dict = Depends(require_admin),
) -> dict:
    """Apply partial updates to the policy for the specified site or group."""
    user_id = current_user.get("userId")
    result = policy_commands.update_policy(
        siteId, groupId, body.model_dump(), user_id,
    )
    return result or {"data": None}
