from collections.abc import Callable
from dataclasses import asdict

from domain.policy import Policy
from repository.activity_repo import activity_repo
from repository.policy_repo import policy_repo
from utils.dt import utc_now


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
        return None

    if not policy:
        return None

    for field, value in updates.items():
        if hasattr(policy, field):
            setattr(policy, field, value)
    policy.updatedAt = utc_now()
    save_fn(policy)
    activity_repo.create(120, "Policy updated", user_id=user_id)
    return {"data": asdict(policy)}
