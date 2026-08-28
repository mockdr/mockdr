"""Splunk user query handlers (read-only)."""

from __future__ import annotations

from repository.splunk.splunk_user_repo import splunk_user_repo
from utils.splunk.response import build_splunk_entry, build_splunk_envelope, complete

# Splunk capability names for role-based access
ADMIN_CAPABILITIES = [
    "admin_all_objects",
    "change_own_password",
    "delete_by_keyword",
    "edit_search_server",
    "edit_user",
    "list_inputs",
    "rest_apps_management",
    "search",
    "schedule_search",
    "accelerate_search",
]

SC_ADMIN_CAPABILITIES = [
    "change_own_password",
    "delete_by_keyword",
    "edit_notable_events",
    "search",
    "schedule_search",
]

USER_CAPABILITIES = [
    "change_own_password",
    "search",
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
        entries.append(
            build_splunk_entry(
                user.username,
                complete(content, "users"),
                collection="authentication/users",
                links=("alternate", "edit", "list"),
                fields=False,
            )
        )
    return build_splunk_envelope(entries, links={"create": "/services/authentication/users/_new"})


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
    # A single read names what the user accepts; the listing does not, and
    # mockdr sent an empty block for both, so a client reading
    # `fields.optional` to learn what it may write learned nothing.
    entry = build_splunk_entry(
        user.username,
        complete(content, "users"),
        collection="authentication/users",
        links=("alternate", "edit", "list"),
        fields=_USER_FIELDS,
    )
    return build_splunk_envelope([entry], total=1)


#: What a user accepts, on a single read (measured on 10.4.2).
_USER_FIELDS = {
    "required": [],
    "optional": [
        "defaultApp", "display_new_search_banner", "email", "force-change-pass",
        "lang", "locked-out", "oldpassword", "olly_org", "password", "realname",
        "restart_background_jobs", "roles", "search_assistant",
        "search_auto_format", "search_line_numbers", "search_syntax_highlighting",
        "search_use_advanced_editor", "theme", "tz",
    ],
    "wildcard": [],
}


def get_current_context(username: str) -> dict:
    """Return current user context for the authenticated user."""
    user = splunk_user_repo.get(username)
    if not user:
        return {}
    content = {
        "username": user.username,
        "realname": user.realname,
        "roles": user.roles,
        "defaultApp": user.default_app,
    }
    return build_splunk_envelope(
        [
            build_splunk_entry(
                username,
                complete(content, "current_context"),
                collection="authentication/users",
                links=("alternate", "list"),
                fields=False,
            )
        ],
        total=1,
        links={},
    )


#: The roles this instance knows, and what each may do.
_ROLES: tuple[dict, ...] = (
    {"name": "admin", "capabilities": ADMIN_CAPABILITIES},
    {"name": "sc_admin", "capabilities": SC_ADMIN_CAPABILITIES},
    {"name": "user", "capabilities": USER_CAPABILITIES},
)

#: What a role accepts, which splunkd lists on a single-role read and not on
#: the listing (measured on 10.4.2).
_ROLE_FIELDS = {
    "required": [],
    "optional": [
        "capabilities", "cumulativeRTSrchJobsQuota", "cumulativeSrchJobsQuota",
        "defaultApp", "deleteIndexesAllowed", "federatedProviders",
        "fieldFilterExemption", "grantable_roles", "imported_roles",
        "kvstore_create.deny_list", "kvstore_create.implicit_deny_list",
        "kvstore_delete.deny_list", "kvstore_delete.implicit_deny_list",
        "kvstore_update.deny_list", "kvstore_update.implicit_deny_list",
        "queuedSearchQuota", "rtSrchJobsQuota", "srchDiskQuota",
        "srchFederatedProvidersAllowed", "srchFederatedProvidersDefault",
        "srchFilter", "srchIndexesAllowed", "srchIndexesDefault",
        "srchIndexesDisallowed", "srchJobsQuota", "srchTimeEarliest",
        "srchTimeWin",
    ],
    "wildcard": [],
}

_ROLE_TOP_LINKS = {"create": "/services/authorization/roles/_new"}


def _role_entry(role: dict, fields: dict | bool) -> dict:
    """One role, as an entry."""
    return build_splunk_entry(
        str(role["name"]),
        complete({k: v for k, v in role.items() if k != "name"}, "roles"),
        collection="authorization/roles",
        links=("alternate", "edit", "list", "remove"),
        fields=fields,
    )


def list_roles() -> dict:
    """Return available roles."""
    return build_splunk_envelope(
        [_role_entry(r, False) for r in _ROLES], links=_ROLE_TOP_LINKS,
    )


def get_role(name: str) -> dict | None:
    """Return one role, the way splunkd addresses it.

    The listing named three roles and nothing would serve any of them: a
    client that listed the roles and then read one — which is what
    splunklib's `.list()` followed by `[name]` does — got 404 for a role the
    listing had just named. A single read also carries the `fields` block
    naming what the role accepts, which the listing does not.
    """
    for role in _ROLES:
        if role["name"] == name:
            return build_splunk_envelope(
                [_role_entry(role, _ROLE_FIELDS)], total=1, links=_ROLE_TOP_LINKS,
            )
    return None


def list_capabilities() -> dict:
    """Return available capabilities."""
    all_caps = sorted(set(ADMIN_CAPABILITIES + SC_ADMIN_CAPABILITIES + USER_CAPABILITIES))
    # A capability is neither created, edited nor removed: splunkd offers no
    # top-level links at all and only `alternate`/`list` on the entry, sends
    # no `fields` block, and carries a null `eai:acl` inside `content`
    # (measured on 10.4.2).
    entry = build_splunk_entry(
        "capabilities",
        {"capabilities": all_caps},
        collection="authorization/capabilities",
        links=("alternate", "list"),
        fields=False,
    )
    entry["content"]["eai:acl"] = None
    return build_splunk_envelope([entry], links={})


def get_capabilities_entry() -> dict:
    """The capabilities collection's single entry, read by name.

    splunkd addresses it as `authorization/capabilities/capabilities`; the
    listing named it and nothing would serve it.
    """
    body = list_capabilities()
    body["entry"][0]["fields"] = {"required": [], "optional": [], "wildcard": []}
    return body
