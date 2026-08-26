"""Cortex XDR RBAC query handlers (read-only)."""
from __future__ import annotations

from infrastructure.seeders.xdr_rbac import XDR_USERS_COLLECTION
from repository.store import store
from utils.xdr_response import build_xdr_reply


def get_users() -> dict:
    """Return the tenant's user directory.

    It was three canned role accounts while every incident was assigned to a
    freshly invented name, so a client that read an incident's
    `assigned_user_mail` and looked the person up here found nobody — every
    time. The directory is seeded now, and incidents are assigned within it.

    Returns:
        XDR list reply with the tenant's users.
    """
    return build_xdr_reply(list(store.get_all(XDR_USERS_COLLECTION)))


def get_user_groups(group_names: list[str] | None = None) -> dict:
    """Return the user groups asked for, or all of them.

    `request_data.group_names` is the one member this route documents, and
    it was read by nothing: a client asking about one group was handed every
    group, and could not tell that its question had been ignored.

    Args:
        group_names: The groups to describe, or None for all of them.

    Returns:
        XDR list reply with the matching group records.
    """
    groups = [
        {"group_name": "XDR Admins", "user_count": 1, "description": "Full access administrators"},
        {"group_name": "SOC Team", "user_count": 1, "description": "Security operations analysts"},
        {"group_name": "Read Only", "user_count": 1, "description": "Read-only viewers"},
    ]
    if group_names:
        wanted = {str(name) for name in group_names}
        groups = [g for g in groups if g["group_name"] in wanted]
    return build_xdr_reply(groups)  # recorded: a bare list in reply


def get_roles() -> dict:
    """Return a synthetic list of XDR roles.

    Returns:
        XDR list reply with canned role records.
    """
    roles = [
        {
            "role_name": "admin",
            "description": "Full access to all XDR features",
            "is_custom": False,
            "permissions": ["*"],
        },
        {
            "role_name": "analyst",
            "description": "Read access everywhere; write for incidents, alerts, actions",
            "is_custom": False,
            "permissions": ["read:*", "write:incidents", "write:alerts", "write:actions"],
        },
        {
            "role_name": "viewer",
            "description": "Read-only access to all features",
            "is_custom": False,
            "permissions": ["read:*"],
        },
    ]
    return build_xdr_reply(roles)  # recorded: a bare list in reply
