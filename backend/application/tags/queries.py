"""Read-only queries for scoped tag definitions."""
from dataclasses import asdict

from repository.agent_repo import agent_repo
from repository.group_repo import group_repo
from repository.site_repo import site_repo
from repository.tag_repo import tag_repo
from utils.filtering import FilterSpec, apply_filters
from utils.pagination import TAG_CURSOR, build_list_response, paginate

FILTER_SPECS = [
    FilterSpec("ids", "id", "in"),
    FilterSpec("key", "key", "eq"),
    FilterSpec("value", "value", "eq"),
    FilterSpec("key__contains", "key", "contains"),
    FilterSpec("value__contains", "value", "contains"),
    FilterSpec("description", "description", "contains"),
    FilterSpec("query", "key|value|description", "full_text"),
    FilterSpec("scopePath", "scopePath", "contains"),
]


def _resolve_scope_ids(
    params: dict,
    include_parents: bool,
    include_children: bool,
) -> set[tuple[str, str]] | None:
    """Return the set of (scopeLevel, scopeId) tuples to include, or None for all.

    When no scope params are given, returns None (no scope filtering).
    """
    site_ids_raw = params.pop("siteIds", None)
    account_ids_raw = params.pop("accountIds", None)
    group_ids_raw = params.pop("groupIds", None)

    if not any([site_ids_raw, account_ids_raw, group_ids_raw]):
        return None

    scopes: set[tuple[str, str]] = set()

    # Parse comma-separated IDs
    site_ids = (
        {s.strip() for s in str(site_ids_raw).split(",") if s.strip()}
        if site_ids_raw else set()
    )
    account_ids = (
        {s.strip() for s in str(account_ids_raw).split(",") if s.strip()}
        if account_ids_raw else set()
    )
    group_ids = (
        {s.strip() for s in str(group_ids_raw).split(",") if s.strip()}
        if group_ids_raw else set()
    )

    # Direct scope matches
    for sid in site_ids:
        scopes.add(("site", sid))
    for aid in account_ids:
        scopes.add(("account", aid))
    for gid in group_ids:
        scopes.add(("group", gid))

    if include_parents:
        # Walk up from each explicit scope
        for sid in site_ids:
            site = site_repo.get(sid)
            if site:
                scopes.add(("account", site.accountId))
                scopes.add(("global", ""))
        for gid in group_ids:
            group = group_repo.get(gid)
            if group:
                scopes.add(("site", group.siteId))
                site = site_repo.get(group.siteId)
                if site:
                    scopes.add(("account", site.accountId))
                scopes.add(("global", ""))
        for _aid in account_ids:
            scopes.add(("global", ""))

    if include_children:
        # Walk down from each explicit scope
        for aid in account_ids:
            for site in site_repo.list_all():
                if site.accountId == aid:
                    scopes.add(("site", site.id))
                    for group in group_repo.list_all():
                        if group.siteId == site.id:
                            scopes.add(("group", group.id))
        for sid in site_ids:
            for group in group_repo.list_all():
                if group.siteId == sid:
                    scopes.add(("group", group.id))

    return scopes


def _compute_endpoint_counts(tag_id: str, scope_level: str, scope_id: str) -> tuple[int, int]:
    """Return (endpointsInCurrentScope, totalEndpoints) for a tag."""
    total = 0
    in_scope = 0
    for agent in agent_repo.list_all():
        agent_tags = (agent.tags or {}).get("sentinelone", [])
        for t in agent_tags:
            if t.get("id") == tag_id:
                total += 1
                if scope_level == "global":
                    in_scope += 1
                elif scope_level == "account" and agent.accountId == scope_id:
                    in_scope += 1
                elif scope_level == "site" and agent.siteId == scope_id:
                    in_scope += 1
                elif scope_level == "group" and agent.groupId == scope_id:
                    in_scope += 1
                break
    return in_scope, total


def list_tags(params: dict, cursor: str | None, limit: int) -> dict:
    """Return a filtered, paginated list of tag definitions.

    Supports ``includeParents`` / ``includeChildren`` scope hierarchy
    traversal and computes per-tag endpoint assignment counts.
    """
    include_parents = str(params.pop("includeParents", "")).lower() in ("true", "1")
    include_children = str(params.pop("includeChildren", "")).lower() in ("true", "1")

    scope_set = _resolve_scope_ids(params, include_parents, include_children)

    records = [asdict(t) for t in tag_repo.list_all()]

    # Scope filtering
    if scope_set is not None:
        records = [
            r for r in records
            if (r["scopeLevel"], r.get("scopeId", "")) in scope_set
        ]

    # Standard field filters
    filtered = apply_filters(records, params, FILTER_SPECS)
    filtered.sort(key=lambda r: r.get("createdAt", ""), reverse=True)

    # Compute endpoint counts and exclusion counts per swagger spec
    for r in filtered:
        in_scope, total = _compute_endpoint_counts(r["id"], r["scopeLevel"], r.get("scopeId", ""))
        r["endpointsInCurrentScope"] = in_scope
        r["totalEndpoints"] = total
        r["totalExclusions"] = 0  # mock: no tag-linked exclusions

    page, next_cursor, total_items = paginate(filtered, cursor, limit, TAG_CURSOR)
    return build_list_response(page, next_cursor, total_items)
