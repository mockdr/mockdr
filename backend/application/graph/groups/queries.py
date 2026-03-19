"""Read-side handlers for Microsoft Graph Groups."""
from __future__ import annotations

from dataclasses import asdict

from repository.graph.group_repo import graph_group_repo
from repository.store import store
from utils.graph_odata import (
    apply_graph_filter,
    apply_odata_orderby,
    apply_odata_search,
    apply_odata_select,
)
from utils.graph_response import build_graph_list_response


def list_groups(
    filter_str: str | None = None,
    top: int = 100,
    skip: int = 0,
    orderby: str | None = None,
    select: str | None = None,
    search: str | None = None,
) -> dict:
    """Return groups with OData query support.

    Args:
        filter_str: OData ``$filter`` expression.
        top:        Page size (``$top``).
        skip:       Number of records to skip (``$skip``).
        orderby:    OData ``$orderby`` expression.
        select:     Comma-separated field list (``$select``).
        search:     OData ``$search`` expression.

    Returns:
        OData list response dict.
    """
    records = [asdict(g) for g in graph_group_repo.list_all()]

    if filter_str:
        records = apply_graph_filter(records, filter_str)
    if search:
        records = apply_odata_search(
            records, search, ["displayName", "description", "mailNickname"],
        )

    records = apply_odata_orderby(records, orderby)
    total = len(records)
    page = records[skip : skip + top]
    page = apply_odata_select(page, select)

    next_link = (
        f"https://graph.microsoft.com/v1.0/groups?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#groups",
        next_link=next_link,
    )


def get_group(group_id: str) -> dict | None:
    """Return a single group by ID.

    Args:
        group_id: The group's ``id``.

    Returns:
        Group dict or ``None`` if not found.
    """
    group = graph_group_repo.get(group_id)
    if group is None:
        return None
    return asdict(group)


def get_group_members(group_id: str) -> dict:
    """Return members of a group.

    Reads from the ``graph_group_members`` collection.

    Args:
        group_id: The group's ``id``.

    Returns:
        OData list response containing member dicts.
    """
    members = store.get("graph_group_members", group_id)
    if not isinstance(members, list):
        members = []

    return build_graph_list_response(
        value=members,
        context=f"https://graph.microsoft.com/v1.0/$metadata#groups('{group_id}')/members",
    )
