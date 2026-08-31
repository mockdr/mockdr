"""CrowdStrike Falcon Quarantine API router.

Implements quarantined-file query and action endpoints used by XSOAR
for managing files quarantined by the Falcon sensor.
"""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Query

from api.cs_auth import require_cs_auth, require_cs_write
from application.cs_quarantine import commands as quarantine_commands
from application.cs_quarantine import queries as quarantine_queries
from utils.cs_response import require_list

router = APIRouter(tags=["CrowdStrike Quarantine"])

#: How many files one by-filter action reaches. The ids route this
#: delegates to takes a page, and an action by filter takes all of them.
_BY_QUERY_LIMIT = 500


@router.get("/quarantine/queries/quarantined-files/v1")
def query_quarantined_files(
    filter: str = Query(None),
    offset: int = Query(0),
    limit: int = Query(100, ge=1, le=500),
    sort: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Query quarantined file IDs with optional FQL filter."""
    return quarantine_queries.query_quarantined_file_ids(filter, offset, limit, sort)


@router.post("/quarantine/entities/quarantined-files/GET/v1")
def get_quarantined_file_entities_by_body(
    body: dict = Body(...),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return full quarantined file entities; ids in the body, as the current API takes them."""
    ids = body.get("ids") if isinstance(body, dict) else None
    response = quarantine_queries.get_quarantined_file_entities(
        [str(i) for i in ids] if isinstance(ids, list) else []
    )
    # DomainAPIQuarantinedFile keeps the name under paths[*].filename only.
    for resource in response.get("resources", []):
        resource.pop("filename", None)
    return response


@router.patch("/quarantine/queries/quarantined-files/v1")
def action_quarantined_files_by_query(
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Apply an action to every quarantined file a filter selects.

    The by-ids twin of this was served and this was not, so a client that
    quarantines by filter — which is what a filter is for — met a 405.
    Body: `{"filter": "<FQL>", "action": "release|delete|unquarantine"}`,
    the shape the reference records (`action`, `comment`, `filter`, `q`).
    """
    selected = quarantine_queries.query_quarantined_file_ids(
        body.get("filter"), 0, _BY_QUERY_LIMIT, None,
    )
    ids = [str(i) for i in selected.get("resources") or []]
    response = quarantine_commands.action_quarantined_files(
        ids, body.get("action", "release"),
    )
    # MsaReplyMetaOnly: meta and errors only, no resources.
    response.pop("resources", None)
    return response


@router.patch("/quarantine/entities/quarantined-files/v1")
def action_quarantined_files(
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Apply an action to quarantined files.

    Body: ``{"ids": [...], "action": "release|delete|unquarantine"}``.
    """
    ids = require_list(body, "ids")
    action = body.get("action", "release")
    response = quarantine_commands.action_quarantined_files(ids, action)
    # MsaReplyMetaOnly: meta and errors only, no resources.
    response.pop("resources", None)
    return response
