"""Cortex XDR RBAC query handlers (read-only)."""
from __future__ import annotations

from utils.xdr_response import build_xdr_list_reply


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
    return build_xdr_list_reply(users, total_count=len(users))


def get_user_groups() -> dict:
    """Return a synthetic list of XDR user groups.

    Returns:
        XDR list reply with canned group records.
    """
    groups = [
        {"group_name": "XDR Admins", "user_count": 1, "description": "Full access administrators"},
        {"group_name": "SOC Team", "user_count": 1, "description": "Security operations analysts"},
        {"group_name": "Read Only", "user_count": 1, "description": "Read-only viewers"},
    ]
    return build_xdr_list_reply(groups, total_count=len(groups))


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
    return build_xdr_list_reply(roles, total_count=len(roles))
