"""Read-side handlers for Microsoft Graph Groups."""
from __future__ import annotations

from repository.graph.group_repo import graph_group_repo
from repository.graph.user_repo import graph_user_repo
from repository.store import store
from utils.graph_odata import (
    apply_graph_filter,
    apply_odata_count,
    apply_odata_orderby,
    apply_odata_search,
    apply_odata_select,
    require_advanced_query,
    select_fields,
)
from utils.graph_response import build_graph_list_response, graph_page
from utils.odata_paging import SKIPTOKEN, page_link
from utils.serde import record_dict


def list_groups(
    filter_str: str | None = None,
    top: int = 100,
    skip: int = 0,
    orderby: str | None = None,
    select: str | None = None,
    search: str | None = None,
    count_param: bool | str | None = None,
    consistency_level: str | None = None,
) -> dict:
    """Return groups with OData query support.

    Args:
        filter_str: OData ``$filter`` expression.
        top:        Page size (``$top``).
        skip:       Number of records to skip (``$skip``).
        orderby:    OData ``$orderby`` expression.
        select:     Comma-separated field list (``$select``).
        search:     OData ``$search`` expression.
        count_param:       Value of ``$count``, which group-list documents and
                           the route did not take.
        consistency_level: Value of the ``ConsistencyLevel`` header.

    Returns:
        OData list response dict.
    """
    require_advanced_query(
        filter_str=filter_str, orderby=orderby, search=search,
        count_param=count_param, consistency_level=consistency_level,
    )
    records = [record_dict(g) for g in graph_group_repo.list_all()]

    if filter_str:
        records = apply_graph_filter(records, filter_str)
    if search:
        records = apply_odata_search(
            records, search, ["displayName", "description", "mailNickname"],
        )

    records = apply_odata_orderby(records, orderby)
    count = apply_odata_count(records, count_param, consistency_level)
    total = len(records)
    page = records[skip : skip + top]
    page = apply_odata_select(page, select)

    next_link = page_link(
        skip + top, total,
        fallback="https://graph.microsoft.com/v1.0/groups", cursor=SKIPTOKEN,
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#groups",
        next_link=next_link,
        count=count,
    )


def get_group(group_id: str, select: str | None = None) -> dict | None:
    """Return a single group by ID.

    Args:
        group_id: The group's ``id``.
        select:   OData ``$select`` expression.

    Returns:
        Group dict or ``None`` if not found.
    """
    group = graph_group_repo.get(group_id)
    if group is None:
        return None
    return select_fields(record_dict(group), select)


def get_group_members(group_id: str, top: int = 100, skip: int = 0) -> dict:
    """Return members of a group.

    Reads from the ``graph_group_members`` collection.

    Args:
        group_id: The group's ``id``.
        top:  ``$top`` -- how many to return.
        skip: ``$skip`` -- how many to pass over first.

    Returns:
        OData list response containing member dicts.
    """
    stored = store.get("graph_group_members", group_id)
    # Graph returns the member as its concrete directoryObject, typed by
    # @odata.type — a user with its full default property set, not the
    # {id, displayName} stub the store keeps.
    members: list[dict] = []
    for member in stored if isinstance(stored, list) else []:
        if not isinstance(member, dict):
            continue
        user = graph_user_repo.get(str(member.get("id", "")))
        if user is not None:
            members.append({"@odata.type": "#microsoft.graph.user", **record_dict(user)})
        else:
            members.append({"@odata.type": "#microsoft.graph.directoryObject", **member})

    page, next_link = graph_page(
        members, top, skip, resource=f"groups/{group_id}/members", cursor=SKIPTOKEN)
    return build_graph_list_response(
        value=page,
        context=f"https://graph.microsoft.com/v1.0/$metadata#groups('{group_id}')/members",
        next_link=next_link,
    )
