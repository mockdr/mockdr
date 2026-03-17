from dataclasses import asdict

from repository.policy_repo import policy_repo
from utils.pagination import build_single_response


def get_policy(site_id: str | None, group_id: str | None) -> dict | None:
    """Return the policy for a site or group, or None if not found.

    Args:
        site_id: Site ID to look up the policy for, if querying by site.
        group_id: Group ID to look up the policy for, if querying by group.

    Returns:
        Wrapped policy dict, or None if neither ID is provided or no policy exists.
    """
    if site_id:
        policy = policy_repo.get_for_site(site_id)
    elif group_id:
        policy = policy_repo.get_for_group(group_id)
    else:
        return None
    return build_single_response(asdict(policy)) if policy else None
