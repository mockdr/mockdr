"""Read-side handlers for Microsoft Graph Users."""
from __future__ import annotations

from dataclasses import asdict

from repository.graph.user_repo import graph_user_repo
from repository.store import store
from utils.graph_odata import (
    apply_graph_filter,
    apply_odata_count,
    apply_odata_orderby,
    apply_odata_search,
    apply_odata_select,
)
from utils.graph_response import build_graph_list_response


def list_users(
    filter_str: str | None = None,
    top: int = 100,
    skip: int = 0,
    orderby: str | None = None,
    select: str | None = None,
    search: str | None = None,
    count_param: bool | str | None = None,
    consistency_level: str | None = None,
) -> dict:
    """Return users with OData query support.

    Args:
        filter_str:        OData ``$filter`` expression.
        top:               Page size (``$top``).
        skip:              Number of records to skip (``$skip``).
        orderby:           OData ``$orderby`` expression.
        select:            Comma-separated field list (``$select``).
        search:            OData ``$search`` expression.
        count_param:       Value of ``$count`` query parameter.
        consistency_level: Value of the ``ConsistencyLevel`` header.

    Returns:
        OData list response dict.
    """
    records = [asdict(u) for u in graph_user_repo.list_all()]

    if filter_str:
        records = apply_graph_filter(records, filter_str)
    if search:
        records = apply_odata_search(
            records, search, ["displayName", "userPrincipalName", "mail"],
        )

    records = apply_odata_orderby(records, orderby)
    count = apply_odata_count(records, count_param, consistency_level)
    total = len(records)
    page = records[skip : skip + top]
    page = apply_odata_select(page, select)
    next_link = (
        f"https://graph.microsoft.com/v1.0/users?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#users",
        next_link=next_link,
        count=count,
    )


def get_user(user_id: str) -> dict | None:
    """Return a single user by ID.

    Args:
        user_id: The user's ``id`` or ``userPrincipalName``.

    Returns:
        User dict or ``None`` if not found.
    """
    user = graph_user_repo.get(user_id)
    if user is None:
        return None
    return asdict(user)


def get_user_member_of(user_id: str) -> dict:
    """Return groups the user belongs to.

    Reads from the ``graph_group_members`` collection and finds groups
    whose member list includes the given user.

    Args:
        user_id: The user's ``id``.

    Returns:
        OData list response containing group membership dicts.
    """
    memberships: list[dict] = []
    # graph_group_members is keyed by group_id → list of user dicts
    groups_collection = store._collections.get("graph_group_members", {})
    for group_id, members in groups_collection.items():
        if isinstance(members, list):
            for member in members:
                member_id = member.get("id") if isinstance(member, dict) else None
                if member_id == user_id:
                    memberships.append({"@odata.type": "#microsoft.graph.group", "id": group_id})
                    break

    return build_graph_list_response(
        value=memberships,
        context="https://graph.microsoft.com/v1.0/$metadata#directoryObjects",
    )


def get_user_mail_rules(user_id: str) -> dict:
    """Return mail rules for a specific user.

    Reads from the ``graph_mail_rules`` collection, filtering entries
    where ``_user_id`` matches the given user.

    Args:
        user_id: The user's ``id``.

    Returns:
        OData list response containing the user's mail rules.
    """
    all_rules = store.get_all("graph_mail_rules")
    rules: list[dict] = []
    for rule in all_rules:
        if isinstance(rule, dict):
            record = dict(rule)
        else:
            record = asdict(rule)
        if record.get("_user_id") == user_id:
            record.pop("_user_id", None)
            rules.append(record)

    return build_graph_list_response(
        value=rules,
        context=f"https://graph.microsoft.com/v1.0/$metadata#users('{user_id}')/mailFolders('inbox')/messageRules",
    )
