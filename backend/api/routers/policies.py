from fastapi import APIRouter, Depends, HTTPException

from api.auth import require_admin
from api.dto.requests import PolicyUpdateBody
from application.accounts import queries as account_queries
from application.policies import commands as policy_commands
from application.policies import queries as policy_queries
from utils.s1_fixtures import restrict_s1
from utils.vendor_errors import build_vendor_error

router = APIRouter(tags=["Policies"])


def _shaped(result: dict | None, definition: str) -> dict:
    """A policy in the shape the 2.1 swagger declares, or the API's empty answer."""
    if not result or result.get("data") is None:
        return {"data": None}
    return restrict_s1(result, definition)


@router.get("/sites/{site_id}/policy")
def get_site_policy(site_id: str) -> dict:
    """Return the site's policy (``GET /sites/{site_id}/policy`` in the 2.1 API)."""
    return _shaped(
        policy_queries.get_policy(site_id, None), "policies_schemas_EnrichedPolicySchema_200"
    )


@router.get("/groups/{group_id}/policy")
def get_group_policy(group_id: str) -> dict:
    """Return the group's policy (``GET /groups/{group_id}/policy`` in the 2.1 API)."""
    return _shaped(
        policy_queries.get_policy(None, group_id), "policies_schemas_EnrichedPolicySchema_200"
    )


@router.get("/accounts/{account_id}/policy")
def get_account_policy(account_id: str) -> dict:
    """Return the account-level policy; the mock keeps one tenant-wide default.

    The account itself has to exist: `/accounts/{id}` answers 404 for one
    that does not, and this route answered the same policy for every id
    anyone could type — including ids the same install had just refused.
    """
    if account_queries.get_account(account_id) is None:
        raise HTTPException(
            status_code=404,
            detail=build_vendor_error(
                "sentinelone", 404, f"Account {account_id} not found"),
        )
    return _shaped(
        policy_queries.get_policy(None, None), "policies_schemas_EnrichedPolicySchema_200"
    )


@router.get("/tenant/policy")
def get_tenant_policy() -> dict:
    """Return the tenant policy (``GET /tenant/policy`` in the 2.1 API)."""
    return _shaped(
        policy_queries.get_policy(None, None), "policies_schemas_EnrichedPolicySchema_200"
    )


@router.put("/sites/{site_id}/policy")
def update_site_policy(
    site_id: str,
    body: PolicyUpdateBody,
    current_user: dict = Depends(require_admin),
) -> dict:
    """Apply partial updates to the site's policy."""
    result = policy_commands.update_policy(
        site_id, None, body.model_dump(), current_user.get("userId")
    )
    return _shaped(result, "policies_schemas_EnrichedPolicySchema_200")


@router.put("/groups/{group_id}/policy")
def update_group_policy(
    group_id: str,
    body: PolicyUpdateBody,
    current_user: dict = Depends(require_admin),
) -> dict:
    """Apply partial updates to the group's policy."""
    result = policy_commands.update_policy(
        None, group_id, body.model_dump(), current_user.get("userId")
    )
    return _shaped(result, "policies_schemas_EnrichedPolicySchema_200")


@router.put("/tenant/policy")
def update_tenant_policy(
    body: PolicyUpdateBody,
    current_user: dict = Depends(require_admin),
) -> dict:
    """Apply partial updates to the tenant policy (``PUT /tenant/policy`` in the 2.1 API)."""
    result = policy_commands.update_policy(
        None, None, body.model_dump(), current_user.get("userId")
    )
    return _shaped(result, "policies_schemas_EnrichedPolicySchema_200")
