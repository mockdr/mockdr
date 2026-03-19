"""Read-side handlers for Microsoft Graph Directory Roles."""
from __future__ import annotations

from dataclasses import asdict

from repository.graph.directory_role_repo import graph_directory_role_repo
from repository.graph.user_repo import graph_user_repo
from repository.store import store
from utils.graph_response import build_graph_list_response


def list_directory_roles() -> dict:
    """Return all directory roles.

    Returns:
        OData list response containing directory role records.
    """
    records = [asdict(r) for r in graph_directory_role_repo.list_all()]
    return build_graph_list_response(
        value=records,
        context="https://graph.microsoft.com/v1.0/$metadata#directoryRoles",
    )


def get_role_members(role_id: str) -> dict:
    """Return users who are members of a directory role.

    Reads from the ``graph_directory_role_members`` collection to get
    the list of user IDs, then looks up each user from the user repo.

    Args:
        role_id: The directory role's ``id``.

    Returns:
        OData list response containing user dicts for role members.
    """
    member_ids = store.get("graph_directory_role_members", role_id)
    members: list[dict] = []
    if isinstance(member_ids, list):
        for uid in member_ids:
            user = graph_user_repo.get(uid)
            if user is not None:
                members.append(asdict(user))

    return build_graph_list_response(
        value=members,
        context=f"https://graph.microsoft.com/v1.0/$metadata#directoryRoles('{role_id}')/members",
    )
