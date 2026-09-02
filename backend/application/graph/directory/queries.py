"""Read-side handlers for Microsoft Graph Directory Roles."""
from __future__ import annotations

from repository.graph.directory_role_repo import graph_directory_role_repo
from repository.graph.user_repo import graph_user_repo
from repository.store import store
from utils.graph_response import build_graph_list_response, graph_page
from utils.serde import record_dict


def list_directory_roles(top: int = 100, skip: int = 0) -> dict:
    """Return all directory roles.

    Args:
        top:  ``$top`` -- how many to return.
        skip: ``$skip`` -- how many to pass over first.

    Returns:
        OData list response containing directory role records.
    """
    records = [record_dict(r) for r in graph_directory_role_repo.list_all()]
    page, next_link = graph_page(records, top, skip, resource="directoryRoles")
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#directoryRoles",
        next_link=next_link,
    )


def get_role_members(role_id: str, top: int = 100, skip: int = 0) -> dict:
    """Return users who are members of a directory role.

    Reads from the ``graph_directory_role_members`` collection to get
    the list of user IDs, then looks up each user from the user repo.

    Args:
        role_id: The directory role's ``id``.
        top:  ``$top`` -- how many to return.
        skip: ``$skip`` -- how many to pass over first.

    Returns:
        OData list response containing user dicts for role members.
    """
    member_ids = store.get("graph_directory_role_members", role_id)
    members: list[dict] = []
    if isinstance(member_ids, list):
        for uid in member_ids:
            user = graph_user_repo.get(uid)
            if user is not None:
                # A directoryObject collection names each item's concrete type.
                members.append({"@odata.type": "#microsoft.graph.user", **record_dict(user)})

    page, next_link = graph_page(
        members, top, skip, resource="directoryRoles/{role_id}/members")
    return build_graph_list_response(
        value=page,
        context=f"https://graph.microsoft.com/v1.0/$metadata#directoryRoles('{role_id}')/members",
        next_link=next_link,
    )
