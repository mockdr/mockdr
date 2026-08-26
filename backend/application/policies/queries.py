
from repository.policy_repo import policy_repo
from utils.pagination import build_single_response
from utils.serde import record_dict


def get_policy(site_id: str | None, group_id: str | None) -> dict | None:
    """Return the policy for a site or group, or None if not found.

    Args:
        site_id: Site ID to look up the policy for, if querying by site.
        group_id: Group ID to look up the policy for, if querying by group.

    Naming neither is the *account* policy — the one a tenant inherits from
    — and not "no policy at all", which is what this used to answer with a
    200 and a null body.

    Returns:
        Wrapped policy dict, or None if no policy exists at that scope.
    """
    if site_id:
        policy = policy_repo.get_for_site(site_id)
    elif group_id:
        policy = policy_repo.get_for_group(group_id)
    else:
        policy = policy_repo.get_for_tenant()
    return build_single_response(record_dict(policy)) if policy else None
