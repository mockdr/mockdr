"""Splunk user query handlers (read-only)."""
from __future__ import annotations

from repository.splunk.splunk_user_repo import splunk_user_repo
from utils.splunk.response import build_splunk_entry, build_splunk_envelope

# Splunk capability names for role-based access
ADMIN_CAPABILITIES = [
    "admin_all_objects", "change_own_password", "delete_by_keyword",
    "edit_search_server", "edit_user", "list_inputs", "rest_apps_management",
    "search", "schedule_search", "accelerate_search",
]

SC_ADMIN_CAPABILITIES = [
    "change_own_password", "delete_by_keyword", "edit_notable_events",
    "search", "schedule_search",
]

USER_CAPABILITIES = [
    "change_own_password", "search",
]


def list_users() -> dict:
    """Return all users in Splunk envelope format."""
    users = splunk_user_repo.list_all()
    entries = []
    for user in users:
        content = {
            "realname": user.realname,
            "email": user.email,
            "roles": user.roles,
            "defaultApp": user.default_app,
            "tz": user.tz,
        }
        entries.append(build_splunk_entry(user.username, content))
    return build_splunk_envelope(entries)


def get_user(username: str) -> dict | None:
    """Return a single user in Splunk envelope format."""
    user = splunk_user_repo.get(username)
    if not user:
        return None
    content = {
        "realname": user.realname,
        "email": user.email,
        "roles": user.roles,
        "defaultApp": user.default_app,
        "tz": user.tz,
    }
    entry = build_splunk_entry(user.username, content)
    return build_splunk_envelope([entry], total=1)


def get_current_context(username: str) -> dict:
    """Return current user context for the authenticated user."""
    user = splunk_user_repo.get(username)
    if not user:
        return {}
    return build_splunk_envelope([build_splunk_entry(username, {
        "username": user.username,
        "realname": user.realname,
        "roles": user.roles,
        "defaultApp": user.default_app,
    })], total=1)


def list_roles() -> dict:
    """Return available roles."""
    roles = [
        {"name": "admin", "capabilities": ADMIN_CAPABILITIES},
        {"name": "sc_admin", "capabilities": SC_ADMIN_CAPABILITIES},
        {"name": "user", "capabilities": USER_CAPABILITIES},
    ]
    entries = [build_splunk_entry(str(r["name"]), r) for r in roles]
    return build_splunk_envelope(entries)


def list_capabilities() -> dict:
    """Return available capabilities."""
    all_caps = sorted(set(ADMIN_CAPABILITIES + SC_ADMIN_CAPABILITIES + USER_CAPABILITIES))
    return build_splunk_envelope(
        [build_splunk_entry("capabilities", {"capabilities": all_caps})],
    )
