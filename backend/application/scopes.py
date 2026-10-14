"""The scope a SentinelOne create body's ``filter`` names.

A create in the 2.1 API -- a tag, an exclusion, a device-control or firewall
rule, a STAR rule -- carries the scope it is created at as a ``filter`` of
``accountIds``, ``siteIds``, ``groupIds`` or ``tenant`` beside its ``data``
(the swagger's ``*_FilterScopeSchema`` bodies).
"""
from __future__ import annotations

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
