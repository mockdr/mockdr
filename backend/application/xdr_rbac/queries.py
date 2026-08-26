"""Cortex XDR RBAC query handlers (read-only)."""
from __future__ import annotations

from utils.xdr_response import build_xdr_reply


def get_users() -> dict:
    """Return a synthetic list of XDR users.

    Returns:
        XDR list reply with canned user records.
    """
    users = [
        {
            "user_email": "admin@acmecorp.internal",
            "user_first_name": "Admin",
            "user_last_name": "User",
            "role": "admin",
            "status": "active",
            "pretty_name": "Admin User",
            "groups": ["XDR Admins"],
        },
        {
            "user_email": "analyst@acmecorp.internal",
            "user_first_name": "SOC",
            "user_last_name": "Analyst",
            "role": "analyst",
            "status": "active",
            "pretty_name": "SOC Analyst",
            "groups": ["SOC Team"],
        },
        {
            "user_email": "viewer@acmecorp.internal",
            "user_first_name": "Viewer",
            "user_last_name": "User",
            "role": "viewer",
            "status": "active",
            "pretty_name": "Viewer User",
            "groups": ["Read Only"],
        },
    ]
    return build_xdr_reply(users)  # recorded: a bare list in reply


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
