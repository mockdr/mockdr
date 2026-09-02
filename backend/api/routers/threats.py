from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from starlette.requests import Request

from api.auth import require_auth, require_write
from api.dto.common import FilterBody
from application.threats import commands as threat_commands
from application.threats import queries as threat_queries
from config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from utils.documented_params import documented_openapi, documented_params

router = APIRouter(tags=["Threats"])


class NoteBody(BaseModel):
    """Request body for adding a threat analyst note."""

    text: str


# ── Queries ───────────────────────────────────────────────────────────────────


@router.get("/threats", openapi_extra=documented_openapi("/threats"))
def list_threats(
    request: Request,
    ids: str = Query(None),
    # `tenant=true` asks for the whole tenant rather than the caller's own
    # scope. mockdr seeds one tenant, and the account scoping a non-admin
    # token carries still applies, so the answer is the same set — but the
    # parameter is declared rather than silently dropped.
    tenant: bool = Query(None),
    accountIds: str = Query(None),
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
    sortBy: str = Query(None),
    sortOrder: str = Query(None),
    skip: int = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a filtered, paginated list of threats."""
    params = {
        k: v for k, v in locals().items()
        if v is not None and k not in ("cursor", "limit", "request")
    }
    params.update(documented_params(request, "/threats"))
    return threat_queries.list_threats(params, cursor, limit)


@router.get("/threats/{threat_id}/timeline")
def get_timeline(
    threat_id: str,
    skip: int = Query(0, ge=0),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
) -> dict:
    """Return the timeline events for the given threat.

    The swagger documents `limit`, `cursor`, `skip` and `skipCount` here, and
    this route took none of them: a client asking for a page of ten got the
    whole timeline with a `nextCursor` of null, which reads as "that was all
    of it".
    """
    result = threat_queries.get_threat_timeline(threat_id, skip, cursor, limit)
    if not result:
        raise HTTPException(status_code=404)
    return result


@router.get("/threats/{threat_id}/notes")
def get_notes(
    threat_id: str,
    skip: int = Query(0, ge=0),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
) -> dict:
    """Return analyst notes for the given threat, a page at a time."""
    result = threat_queries.get_threat_notes(threat_id, skip, cursor, limit)
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


@router.get("/threats/{threat_id}/download-from-cloud")
def download_fetched_file(threat_id: str, _: dict = Depends(require_auth)) -> Response:
    """Download the fetched file for the given threat (legacy path)."""
    return _download_threat_file(threat_id)


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


# There were `POST /threats/mark-as-threat` and `POST
# /threats/mark-as-resolved` here. Neither is in the 2.1 swagger — the only
# `mark-as-threat` it publishes is `dv-mark-as-threat`, and
# `mark-as-resolved` appears nowhere at all. SentinelOne records both
# through `/threats/analyst-verdict` and `/threats/incident`, which this
# mock serves and which do the same work: `param_drift.py` had been listing
# these two among the routes the vendor does not publish, and nothing ran it.


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
