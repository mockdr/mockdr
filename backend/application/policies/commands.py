from collections.abc import Callable

from domain.policy import Policy
from repository.activity_repo import activity_repo
from repository.policy_repo import policy_repo
from repository.user_repo import user_repo
from utils.dt import utc_now
from utils.serde import record_dict

#: Members of the policy document the caller may not set.
_SERVER_OWNED = frozenset({"createdAt", "updatedAt", "userId", "userFullName", "id",
                           "scopeId", "scopeType"})


def update_policy(
    site_id: str | None,
    group_id: str | None,
    updates: dict,
    user_id: str | None,
) -> dict | None:
    """Apply partial updates to a site or group policy.

    Args:
        site_id: Site ID whose policy to update, if updating by site.
        group_id: Group ID whose policy to update, if updating by group.
        updates: Dict of field names to new values to apply to the policy.
        user_id: ID of the acting user, if authenticated.

    Returns:
        Dict with ``data`` containing the updated policy, or None if not found.
    """
    save_fn: Callable
    if site_id:
        policy = policy_repo.get_for_site(site_id)

        def save_fn(p: Policy) -> None:
            policy_repo.save_for_site(site_id, p)

    elif group_id:
        policy = policy_repo.get_for_group(group_id)

        def save_fn(p: Policy) -> None:
            policy_repo.save_for_group(group_id, p)

    else:
        # The tenant policy, which `PUT /tenant/policy` and
        # `PUT /accounts/{id}/policy` change. Returning None here meant both
        # answered 200 with `data: null` and changed nothing — an update
        # that reports neither success nor failure.
        policy = policy_repo.get_for_tenant()

        def save_fn(p: Policy) -> None:
            policy_repo.save_for_tenant(p)

    if not policy:
        return None

    # The 2.1 API wraps a policy change in `data`, and every one of these
    # routes passed the wrapper straight in: `hasattr(policy, "data")` is
    # false, so nothing was ever set and all three answered 200 with the
    # policy unchanged.
    wrapped = updates.get("data")
    changes: dict = wrapped if isinstance(wrapped, dict) else updates
    for field, value in changes.items():
        # Four members the record carries belong to the server, not the
        # caller: when the policy was made, and who last changed it. The
        # swagger lists them in the body schema alongside the settings, so a
        # client sending the whole document back would otherwise rewrite its
        # own audit trail.
        if field in _SERVER_OWNED:
            continue
        if hasattr(policy, field):
            setattr(policy, field, value)
    policy.updatedAt = utc_now()
    if user_id:
        policy.userId = user_id
        user = user_repo.get(user_id)
        policy.userFullName = getattr(user, "fullName", "") if user else ""
    save_fn(policy)
    activity_repo.create(120, "Policy updated", user_id=user_id)
    return {"data": record_dict(policy)}
