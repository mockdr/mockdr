from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel

from api.auth import require_auth, require_write
from api.dto.common import FilterBody
from application.threats import commands as threat_commands
from application.threats import queries as threat_queries
from config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE

router = APIRouter(tags=["Threats"])


class NoteBody(BaseModel):
    """Request body for adding a threat analyst note."""

    text: str


# ── Queries ───────────────────────────────────────────────────────────────────

@router.get("/threats")
def list_threats(
    ids: str = Query(None),
    siteIds: str = Query(None),
    groupIds: str = Query(None),
    agentIds: str = Query(None),
    classifications: str = Query(None),
    mitigationStatuses: str = Query(None),
    analystVerdicts: str = Query(None),
    incidentStatuses: str = Query(None),
    confidenceLevels: str = Query(None),
    resolved: str = Query(None),
    contentHashes: str = Query(None),
    threatName: str = Query(None),
    query: str = Query(None),
    createdAt__gte: str = Query(None),
    createdAt__lte: str = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a filtered, paginated list of threats."""
    params = {k: v for k, v in locals().items() if v is not None and k not in ("cursor", "limit")}
    return threat_queries.list_threats(params, cursor, limit)


@router.get("/threats/{threat_id}/timeline")
def get_timeline(threat_id: str) -> dict:
    """Return the timeline events for the given threat."""
    result = threat_queries.get_threat_timeline(threat_id)
    if not result:
        raise HTTPException(status_code=404)
    return result


@router.get("/threats/{threat_id}/notes")
def get_notes(threat_id: str) -> dict:
    """Return analyst notes for the given threat."""
    result = threat_queries.get_threat_notes(threat_id)
    if not result:
        raise HTTPException(status_code=404)
    return result


def _download_threat_file(threat_id: str) -> Response:
    """Shared handler for threat file download (both path variants)."""
    result = threat_queries.get_fetched_file(threat_id)
    if not result:
        raise HTTPException(
            status_code=404,
            detail="No fetched file available. Call POST /threats/fetch-file first.",
        )
    file_bytes, filename = result
    return Response(
        content=file_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/threats/{threat_id}/fetch-file")
def download_fetch_file(threat_id: str, _: dict = Depends(require_auth)) -> Response:
    """Download the fetched file for the given threat (XSOAR-compatible path)."""
    return _download_threat_file(threat_id)


@router.get("/threats/{threat_id}/fetched-file")
def download_fetched_file(threat_id: str, _: dict = Depends(require_auth)) -> Response:
    """Download the fetched file for the given threat (legacy path)."""
    return _download_threat_file(threat_id)


@router.get("/threats/{threat_id}")
def get_threat(threat_id: str) -> dict:
    """Return a single threat by ID."""
    result = threat_queries.get_threat(threat_id)
    if not result:
        raise HTTPException(status_code=404)
    return result


# ── Commands (real S1 API paths) ──────────────────────────────────────────────

@router.post("/threats/analyst-verdict")
def set_analyst_verdict(body: FilterBody, current_user: dict = Depends(require_write)) -> dict:
    """Set the analyst verdict on the specified threats."""
    ids = body.filter.get("ids", [])
    verdict = body.data.get("analystVerdict", "undefined")
    return threat_commands.set_analyst_verdict(verdict, ids, current_user.get("userId"))


@router.post("/threats/incident")
def set_incident_status(body: FilterBody, current_user: dict = Depends(require_write)) -> dict:
    """Set the incident status on the specified threats."""
    ids = body.filter.get("ids", [])
    status = body.data.get("incidentStatus", "unresolved")
    return threat_commands.set_incident_status(status, ids, current_user.get("userId"))


@router.post("/threats/mitigate/{action}")
def mitigate_threat(
    action: str, body: FilterBody, current_user: dict = Depends(require_write)
) -> dict:
    """Apply a mitigation action to the specified threats."""
    ids = body.filter.get("ids", [])
    return threat_commands.mitigate(action, ids, current_user.get("userId"))


@router.post("/threats/add-to-blacklist")
def add_to_blacklist(body: FilterBody, current_user: dict = Depends(require_write)) -> dict:
    """Add the hashes of the specified threats to the blocklist."""
    ids = body.filter.get("ids", [])
    return threat_commands.add_to_blacklist(ids, body.data, current_user.get("userId"))


@router.post("/threats/mark-as-threat")
def mark_as_threat(body: FilterBody, current_user: dict = Depends(require_write)) -> dict:
    """Mark the specified threats as confirmed malicious."""
    ids = body.filter.get("ids", [])
    return threat_commands.mark_as_threat(ids, current_user.get("userId"))


@router.post("/threats/mark-as-resolved")
def mark_as_resolved(body: FilterBody, current_user: dict = Depends(require_write)) -> dict:
    """Mark the specified threats as resolved."""
    ids = body.filter.get("ids", [])
    return threat_commands.mark_as_resolved(ids, current_user.get("userId"))


@router.post("/threats/notes")
def bulk_add_notes(body: FilterBody, current_user: dict = Depends(require_write)) -> dict:
    """Append an analyst note to a list of threats.

    Body: ``{"data": {"text": "..."}, "filter": {"ids": [...]}}``.
    """
    ids = body.filter.get("ids", [])
    text = body.data.get("text", "")
    return threat_commands.bulk_add_notes(ids, text, current_user.get("userId"))


@router.post("/threats/{threat_id}/notes")
def add_note(
    threat_id: str,
    body: NoteBody,
    current_user: dict = Depends(require_write),
) -> dict:
    """Append an analyst note to the given threat."""
    result = threat_commands.add_note(threat_id, body.text, current_user.get("userId"))
    if not result:
        raise HTTPException(status_code=404)
    return result



@router.post("/threats/fetch-file")
def fetch_file(body: FilterBody, current_user: dict = Depends(require_write)) -> dict:
    """Queue a file fetch from the agent for the specified threats."""
    ids = body.filter.get("ids", [])
    return threat_commands.fetch_file(ids, current_user.get("userId"))


@router.post("/threats/dv-add-to-blacklist")
def dv_add_to_blacklist(body: FilterBody, current_user: dict = Depends(require_write)) -> dict:
    """Add hashes of the specified threats (from DV context) to the blocklist."""
    ids = body.filter.get("ids", [])
    return threat_commands.dv_add_to_blacklist(ids, body.data, current_user.get("userId"))


@router.post("/threats/dv-mark-as-threat")
def dv_mark_as_threat(body: FilterBody, current_user: dict = Depends(require_write)) -> dict:
    """Mark threats as confirmed malicious (from Deep Visibility context)."""
    ids = body.filter.get("ids", [])
    return threat_commands.dv_mark_as_threat(ids, current_user.get("userId"))


@router.post("/threats/engines/disable")
def disable_engines(body: FilterBody, current_user: dict = Depends(require_write)) -> dict:
    """Disable detection engines on agents hosting the specified threats."""
    ids = body.filter.get("ids", [])
    return threat_commands.disable_engines(ids, current_user.get("userId"))
