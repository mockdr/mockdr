"""The scope a SentinelOne create body's ``filter`` names.

A create in the 2.1 API -- a tag, an exclusion, a device-control or firewall
rule, a STAR rule -- carries the scope it is created at as a ``filter`` of
``accountIds``, ``siteIds``, ``groupIds`` or ``tenant`` beside its ``data``
(the swagger's ``*_FilterScopeSchema`` bodies).
"""
from __future__ import annotations

from dataclasses import dataclass

from repository.account_repo import account_repo
from repository.group_repo import group_repo
from repository.site_repo import site_repo


def resolve_scope(filter_obj: dict) -> tuple[str, str, str]:
    """Determine scope level, scope ID, and scope path from the filter object.

    The most specific member wins: ``tenant``, then the first of
    ``groupIds``, ``siteIds``, ``accountIds``; none of them is the global
    scope.

    Returns:
        (scopeLevel, scopeId, scopePath)
    """
    if filter_obj.get("tenant"):
        return "global", "", "Global"

    group_ids = filter_obj.get("groupIds", [])
    if group_ids:
        gid = group_ids[0] if isinstance(group_ids, list) else str(group_ids).split(",")[0]
        group = group_repo.get(gid)
        if group:
            site = site_repo.get(group.siteId)
            account_name = group.accountName or "Global"
            site_name = group.siteName or (site.name if site else "")
            path = f"Global\\{account_name}\\{site_name}\\{group.name}"
            return "group", gid, path
        return "group", gid, "Global"

    site_ids = filter_obj.get("siteIds", [])
    if site_ids:
        sid = site_ids[0] if isinstance(site_ids, list) else str(site_ids).split(",")[0]
        site = site_repo.get(sid)
        if site:
            path = f"Global\\{site.accountName}\\{site.name}"
            return "site", sid, path
        return "site", sid, "Global"

    account_ids = filter_obj.get("accountIds", [])
    if account_ids:
        aid = account_ids[0] if isinstance(account_ids, list) else str(account_ids).split(",")[0]
        account = account_repo.get(aid)
        if account:
            return "account", aid, f"Global\\{account.name}"
        return "account", aid, "Global"

    return "global", "", "Global"


#: The members of a create body's scope filter.
_SCOPE_MEMBERS = ("tenant", "groupIds", "siteIds", "accountIds")


@dataclass(frozen=True)
class FilterScope:
    """Where a create's ``filter`` puts the new record, in each shape a record keeps it.

    Attributes:
        level:      ``global``, ``account``, ``site`` or ``group``.
        scope_id:   The id at that level; empty for ``global``.
        name:       The scope's display name (the account, site or group name).
        path:       ``Global / <account> / <site> / <group>``.
        site_id:    The site the scope sits in; empty above site level.
        account_id: The account the scope sits in; empty for ``global``.
        members:    The filter's own scope members, as the restrictions and
                    exclusions records keep them.
    """

    level: str
    scope_id: str
    name: str
    path: str
    site_id: str
    account_id: str
    members: dict


def filter_scope(filter_obj: object) -> FilterScope | None:
    """The scope a create body's ``filter`` names, or None when it names none."""
    if not isinstance(filter_obj, dict) or not any(filter_obj.get(m) for m in _SCOPE_MEMBERS):
        return None
    level, scope_id, path = resolve_scope(filter_obj)
    name, site_id, account_id = "Global", "", ""
    if level == "group":
        group = group_repo.get(scope_id)
        name = group.name if group else scope_id
        site_id = group.siteId if group else ""
        site = site_repo.get(site_id) if site_id else None
        account_id = (group.accountId if group else "") or (site.accountId if site else "")
    elif level == "site":
        site = site_repo.get(scope_id)
        name, site_id = (site.name if site else scope_id), scope_id
        account_id = site.accountId if site else ""
    elif level == "account":
        account = account_repo.get(scope_id)
        name, account_id = (account.name if account else scope_id), scope_id
    members = {m: filter_obj[m] for m in _SCOPE_MEMBERS if filter_obj.get(m)}
    return FilterScope(
        level=level, scope_id=scope_id, name=name, path=path.replace("\\", " / "),
        site_id=site_id, account_id=account_id, members=members,
    )
