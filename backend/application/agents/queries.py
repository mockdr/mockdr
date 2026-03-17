import json
from dataclasses import asdict

from infrastructure.process_gen import generate_processes_for_agent
from repository.agent_repo import agent_repo
from repository.store import store
from utils.filtering import FilterSpec, apply_filters
from utils.internal_fields import AGENT_INTERNAL_FIELDS
from utils.pagination import AGENT_CURSOR, build_list_response, build_single_response, paginate
from utils.strip import strip_fields

FILTER_SPECS = [
    FilterSpec("ids", "id", "in"),
    FilterSpec("accountIds", "accountId", "in"),
    FilterSpec("siteIds", "siteId", "in"),
    FilterSpec("groupIds", "groupId", "in"),
    FilterSpec("osTypes", "osType", "in"),
    FilterSpec("networkStatuses", "networkStatus", "in"),
    FilterSpec("isActive", "isActive", "bool"),
    FilterSpec("isDecommissioned", "isDecommissioned", "bool"),
    FilterSpec("infected", "infected", "bool"),
    FilterSpec("isPendingUninstall", "isPendingUninstall", "bool"),
    FilterSpec("isUpToDate", "isUpToDate", "bool"),
    FilterSpec("computerName", "computerName", "contains"),
    FilterSpec("query", "computerName|localIp|externalIp|osName|domain", "full_text"),
    FilterSpec("registeredAt__gte", "registeredAt", "gte_dt"),
    FilterSpec("registeredAt__lte", "registeredAt", "lte_dt"),
    FilterSpec("updatedAt__gte", "updatedAt", "gte_dt"),
    FilterSpec("decommissionedAt__gte", "decommissionedAt", "gte_dt"),
]


def _apply_tag_filters(records: list[dict], params: dict) -> list[dict]:
    """Apply hasTags and tagsData post-filters to agent records."""
    has_tags = params.pop("hasTags", None)
    tags_data_raw = params.pop("tagsData", None)

    if has_tags is not None:
        want = str(has_tags).lower() in ("true", "1", "yes")
        records = [
            r for r in records
            if bool((r.get("tags") or {}).get("sentinelone", [])) == want
        ]

    if tags_data_raw:
        try:
            tag_filter = (
                json.loads(tags_data_raw) if isinstance(tags_data_raw, str)
                else tags_data_raw
            )
        except (json.JSONDecodeError, TypeError):
            tag_filter = {}
        for key_expr, values in tag_filter.items():
            if not isinstance(values, list):
                values = [values]
            negate = key_expr.endswith("__nin")
            tag_key = key_expr.removesuffix("__nin")
            filtered = []
            for r in records:
                s1_tags = (r.get("tags") or {}).get("sentinelone", [])
                agent_vals = {t["value"] for t in s1_tags if t.get("key") == tag_key}
                has_match = bool(agent_vals & set(values))
                if negate:
                    if not has_match:
                        filtered.append(r)
                else:
                    if has_match:
                        filtered.append(r)
            records = filtered

    return records


def list_agents(params: dict, cursor: str | None, limit: int) -> dict:
    """Return a filtered, paginated list of agents sorted by last active date."""
    records = [asdict(a) for a in agent_repo.list_all()]
    records = _apply_tag_filters(records, params)
    filtered = apply_filters(records, params, FILTER_SPECS)
    filtered.sort(key=lambda r: r.get("lastActiveDate", ""), reverse=True)
    page, next_cursor, total = paginate(filtered, cursor, limit, AGENT_CURSOR)
    stripped = [strip_fields(r, AGENT_INTERNAL_FIELDS) for r in page]
    return build_list_response(stripped, next_cursor, total)


def count_agents(params: dict) -> dict:
    """Return the count of agents matching the given filter parameters."""
    records = [asdict(a) for a in agent_repo.list_all()]
    filtered = apply_filters(records, params, FILTER_SPECS)
    return {"data": {"count": len(filtered)}}


def list_passphrases(params: dict, cursor: str | None, limit: int) -> dict:
    """Return a paginated list of agent passphrases matching the given filters."""
    records = [asdict(a) for a in agent_repo.list_all()]
    filtered = apply_filters(records, params, FILTER_SPECS)
    passphrases = [
        {"agentId": r["id"], "computerName": r["computerName"], "passphrase": r["passphrase"]}
        for r in filtered
    ]
    page, next_cursor, total = paginate(passphrases, cursor, limit)
    return build_list_response(page, next_cursor, total)



def get_agent(agent_id: str) -> dict | None:
    """Return a single agent by ID with internal fields stripped, or None."""
    agent = agent_repo.get(agent_id)
    if not agent:
        return None
    return build_single_response(strip_fields(asdict(agent), AGENT_INTERNAL_FIELDS))


def get_agent_passphrase(agent_id: str) -> dict | None:
    """Return the disk-encryption passphrase for a given agent, or None."""
    agent = agent_repo.get(agent_id)
    if not agent:
        return None
    return {"data": {"passphrase": agent.passphrase}}


def get_agent_processes(agent_id: str, cursor: str | None, limit: int) -> dict | None:
    """Return a paginated list of running processes for the given agent, or None."""
    if not agent_repo.exists(agent_id):
        return None
    processes = generate_processes_for_agent(agent_id)
    page, next_cursor, total = paginate(processes, cursor, limit)
    return build_list_response(page, next_cursor, total)


def get_agent_applications(agent_id: str, cursor: str | None, limit: int) -> dict | None:
    """Return a paginated list of installed applications for the given agent, or None."""
    if not agent_repo.exists(agent_id):
        return None
    apps = [
        r for r in store.get_all("installed_apps")
        if r.get("agentId") == agent_id
    ]
    page, next_cursor, total = paginate(apps, cursor, limit)
    return build_list_response(page, next_cursor, total)


def list_applications_for_agents(
    agent_ids: list[str],
    cursor: str | None,
    limit: int,
    agent_is_decommissioned: str | None = None,
    installed_at_between: str | None = None,
) -> dict:
    """Return installed applications across multiple agents (global endpoint).

    When ``agent_ids`` is empty, returns applications for all agents.

    Args:
        agent_ids: List of S1 agent IDs to filter by. Empty = all agents.
        cursor: Pagination cursor.
        limit: Page size.
        agent_is_decommissioned: Filter by agent decommission status (``"true"``/``"false"``).
        installed_at_between: Date range filter ``"START,END"`` for ``installedDate``.
    """
    apps = store.get_all("installed_apps")

    if agent_ids:
        agent_id_set = set(agent_ids)
        apps = [r for r in apps if r.get("agentId") in agent_id_set]

    # Filter by agent decommission status
    if agent_is_decommissioned is not None:
        want_decomm = str(agent_is_decommissioned).lower() in ("true", "1")
        decomm_agents: set[str] = set()
        for agent in agent_repo.list_all():
            if agent.isDecommissioned == want_decomm:
                decomm_agents.add(agent.id)
        apps = [r for r in apps if r.get("agentId") in decomm_agents]

    # Filter by installedAt date range
    if installed_at_between:
        from utils.filtering import _parse_dt
        parts = installed_at_between.split(",", 1)
        if len(parts) == 2:
            start_dt = _parse_dt(parts[0].strip())
            end_dt = _parse_dt(parts[1].strip())
            if start_dt and end_dt:
                filtered: list[dict] = []
                for r in apps:
                    dt = _parse_dt(str(r.get("installedDate", "") or ""))
                    if dt and start_dt <= dt <= end_dt:
                        filtered.append(r)
                apps = filtered

    page, next_cursor, total = paginate(apps, cursor, limit)
    return build_list_response(page, next_cursor, total)


def list_processes_for_agents(agent_ids: list[str], cursor: str | None, limit: int) -> dict:
    """Return running processes across multiple agents (global endpoint).

    When ``agent_ids`` is empty, returns processes for all agents (up to limit).
    """
    all_agents = agent_repo.list_all()
    targets = [a for a in all_agents if not agent_ids or a.id in agent_ids]
    processes: list[dict] = []
    for agent in targets:
        processes.extend(generate_processes_for_agent(agent.id))
    page, next_cursor, total = paginate(processes, cursor, limit)
    return build_list_response(page, next_cursor, total)


def get_agent_upload(agent_id: str, activity_id: str) -> bytes | None:
    """Return the zip bytes for a previously queued file fetch, or None.

    Implements the backing query for GET /agents/{id}/uploads/{activity_id}.
    The agent_id is validated (must exist) but the upload is keyed only by
    activity_id, which is how the real S1 API works.

    Args:
        agent_id: ID of the agent (validated but not used as key).
        activity_id: ID of the activity created by ``fetch_files``.

    Returns:
        Raw zip bytes if found, or None if agent or upload does not exist.
    """
    if not agent_repo.get(agent_id):
        return None
    return store.get("agent_uploads", activity_id)
