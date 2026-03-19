from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

from api.auth import require_auth, require_write
from api.dto.common import BulkActionBody
from api.dto.requests import FetchFilesBody, RemoteScriptBody
from application.agents import commands as agent_commands
from application.agents import queries as agent_queries
from application.tags import queries as tag_queries
from config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE

router = APIRouter(tags=["Agents"])


# ── Static sub-resource endpoints (must come before /{agent_id}) ──────────────

@router.get("/agents/count")
def count_agents(
    siteIds: str = Query(None),
    groupIds: str = Query(None),
    osTypes: str = Query(None),
    networkStatuses: str = Query(None),
    isActive: str = Query(None),
    infected: str = Query(None),
    isDecommissioned: str = Query(None),
) -> dict:
    """Return the count of agents matching the given filter parameters."""
    params = {k: v for k, v in locals().items() if v is not None}
    return agent_queries.count_agents(params)


@router.get("/agents/tags")
def list_tags(
    siteIds: str = Query(None),
    accountIds: str = Query(None),
    groupIds: str = Query(None),
    includeParents: str = Query(None),
    includeChildren: str = Query(None),
    ids: str = Query(None),
    key: str = Query(None),
    key__contains: str = Query(None),
    value: str = Query(None),
    value__contains: str = Query(None),
    description: str = Query(None),
    query: str = Query(None),
    scopePath: str = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a filtered, paginated list of scoped tag definitions."""
    params = {k: v for k, v in locals().items() if v is not None and k not in ("cursor", "limit")}
    return tag_queries.list_tags(params, cursor, limit)


@router.get("/agents/passphrases")
def list_passphrases(
    siteIds: str = Query(None),
    groupIds: str = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a paginated list of agent disk-encryption passphrases."""
    params = {k: v for k, v in locals().items() if v is not None and k not in ("cursor", "limit")}
    return agent_queries.list_passphrases(params, cursor, limit)


@router.get("/installed-applications")
def list_installed_applications(
    ids: str = Query(None),
    agentIds: str = Query(None),
    agentIsDecommissioned: str = Query(None),
    installedAt__between: str = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a paginated list of installed applications (top-level endpoint).

    Accepts ``?ids=`` (application-level) or ``?agentIds=`` for agent-scoped queries.
    Supports ``?agentIsDecommissioned=false`` and ``?installedAt__between=START,END``
    filters matching the real S1 API contract.
    """
    agent_ids = [i.strip() for i in agentIds.split(",") if i.strip()] if agentIds else []
    return agent_queries.list_applications_for_agents(
        agent_ids, cursor, limit,
        agent_is_decommissioned=agentIsDecommissioned,
        installed_at_between=installedAt__between,
    )


@router.get("/agents/applications")
def list_agent_applications(
    ids: str = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
) -> dict:
    """Return installed applications filtered by agent IDs (global endpoint).

    Accepts ``?ids=<agentId1>,<agentId2>`` matching the real S1 API contract.
    """
    agent_ids = [i.strip() for i in ids.split(",") if i.strip()] if ids else []
    return agent_queries.list_applications_for_agents(agent_ids, cursor, limit)


@router.get("/agents/processes")
def list_agent_processes(
    ids: str = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
) -> dict:
    """Return running processes filtered by agent IDs (global endpoint).

    Accepts ``?ids=<agentId1>,<agentId2>`` matching the real S1 API contract.
    """
    agent_ids = [i.strip() for i in ids.split(",") if i.strip()] if ids else []
    return agent_queries.list_processes_for_agents(agent_ids, cursor, limit)


# ── List + actions ────────────────────────────────────────────────────────────

@router.get("/agents")
def list_agents(
    ids: str = Query(None),
    siteIds: str = Query(None),
    groupIds: str = Query(None),
    osTypes: str = Query(None),
    networkStatuses: str = Query(None),
    isActive: str = Query(None),
    isDecommissioned: str = Query(None),
    infected: str = Query(None),
    isPendingUninstall: str = Query(None),
    isUpToDate: str = Query(None),
    computerName: str = Query(None),
    query: str = Query(None),
    registeredAt__gte: str = Query(None),
    registeredAt__lte: str = Query(None),
    updatedAt__gte: str = Query(None),
    decommissionedAt__gte: str = Query(None),
    hasTags: str = Query(None),
    tagsData: str = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a filtered, paginated list of agents."""
    params = {k: v for k, v in locals().items() if v is not None and k not in ("cursor", "limit")}
    return agent_queries.list_agents(params, cursor, limit)


@router.post("/agents/actions/{action_name}")
def agent_action(
    action_name: str,
    body: BulkActionBody,
    current_user: dict = Depends(require_write),
) -> dict:
    """Apply a named action to the specified agents."""
    try:
        return agent_commands.execute_action(
            action_name, body.model_dump(), current_user.get("userId")
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ── Per-agent endpoints ────────────────────────────────────────────────────────

@router.get("/agents/{agent_id}/passphrase")
def get_passphrase(agent_id: str) -> dict:
    """Return the disk-encryption passphrase for the given agent."""
    result = agent_queries.get_agent_passphrase(agent_id)
    if not result:
        raise HTTPException(status_code=404)
    return result


@router.get("/agents/{agent_id}/processes")
def get_processes(
    agent_id: str,
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a paginated list of running processes for the given agent."""
    result = agent_queries.get_agent_processes(agent_id, cursor, limit)
    if not result:
        raise HTTPException(status_code=404)
    return result


@router.get("/agents/{agent_id}/applications")
def get_agent_apps(
    agent_id: str,
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a paginated list of installed applications for the given agent."""
    result = agent_queries.get_agent_applications(agent_id, cursor, limit)
    if not result:
        raise HTTPException(status_code=404)
    return result


@router.post("/agents/{agent_id}/actions/fetch-files")
def fetch_files(
    agent_id: str,
    body: FetchFilesBody,
    current_user: dict = Depends(require_write),
) -> dict:
    """Queue a file collection from an agent and prepare it for download.

    Body: ``{"data": {"password": "...", "files": ["path"]}}``.
    Creates an activity whose ID is the key for the subsequent upload download.
    """
    data = body.data
    files = data.get("files", [])
    password = data.get("password", "")
    return agent_commands.fetch_files(agent_id, files, password, current_user.get("userId"))


@router.get("/agents/{agent_id}/uploads/{activity_id}")
def download_agent_upload(
    agent_id: str,
    activity_id: str,
    _: dict = Depends(require_auth),
) -> Response:
    """Download a file collected from an agent by a previous fetch-files request.

    Returns the zip archive as ``application/zip``.
    """
    zip_bytes = agent_queries.get_agent_upload(agent_id, activity_id)
    if not zip_bytes:
        raise HTTPException(status_code=404, detail="Upload not found")
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{activity_id}.zip"'},
    )


@router.post("/remote-scripts/execute")
def execute_remote_script(
    body: RemoteScriptBody,
    current_user: dict = Depends(require_write),
) -> dict:
    """Execute a remote script on specified agents.

    Body: ``{"data": {"scriptId": "...", ...}, "filter": {"ids": [...]}}``.
    Implements POST /remote-scripts/execute matching the real S1 API.
    Returns a simulated execution record.
    """
    return agent_commands.execute_remote_script(body.model_dump(), current_user.get("userId"))


@router.get("/agents/{agent_id}")
def get_agent(agent_id: str) -> dict:
    """Return a single agent by ID."""
    result = agent_queries.get_agent(agent_id)
    if not result:
        raise HTTPException(status_code=404)
    return result
