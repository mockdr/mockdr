from fastapi import APIRouter, Depends, HTTPException, Query

from api.auth import require_admin
from api.dto.requests import BulkDeleteBody
from application.exclusions import commands as exclusion_commands
from application.exclusions import queries as exclusion_queries
from config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from repository.blocklist_repo import blocklist_repo
from repository.exclusion_repo import exclusion_repo
from utils.dt import utc_now
from utils.filtering import FilterSpec, apply_filters
from utils.id_gen import new_id
from utils.pagination import (
    RESTRICTION_CURSOR,
    build_list_response,
    build_single_response,
    paginate,
)

router = APIRouter(tags=["Exclusions & Blocklist"])

_BLOCKLIST_SPECS = [
    FilterSpec("siteIds", "siteId", "in"),
    FilterSpec("types", "type", "in"),
]

_BLOCKLIST_INTERNAL = {"siteId"}


@router.get("/exclusions")
def list_exclusions(
    ids: str = Query(None),
    siteIds: str = Query(None),
    type: str = Query(None),
    types: str = Query(None),
    osTypes: str = Query(None),
    value__contains: str = Query(None),
    includeChildren: bool = Query(None),
    includeParents: bool = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a filtered, paginated list of threat exclusions.

    Accepts both ``type`` (singular) and ``types`` (plural) query parameters.
    """
    params = {k: v for k, v in locals().items() if v is not None and k not in ("cursor", "limit")}
    # ``type`` (singular) is normalised to ``types`` for the filter engine
    if "type" in params and "types" not in params:
        params["types"] = params.pop("type")
    else:
        params.pop("type", None)
    return exclusion_queries.list_exclusions(params, cursor, limit)


@router.post("/exclusions")
def create_exclusion(body: dict, current_user: dict = Depends(require_admin)) -> dict:
    """Create a new threat exclusion.

    Accepts both flat and wrapped (``{"data": {...}}``) payloads per real S1 API.
    """
    return exclusion_commands.create_exclusion(body, current_user.get("userId"))


@router.put("/exclusions/{exclusion_id}")
def update_exclusion(
    exclusion_id: str, body: dict, current_user: dict = Depends(require_admin)
) -> dict:
    """Update an existing threat exclusion by ID."""
    result = exclusion_commands.update_exclusion(exclusion_id, body, current_user.get("userId"))
    if result is None:
        raise HTTPException(status_code=404, detail="Exclusion not found")
    return result


@router.delete("/exclusions")
def bulk_delete_exclusions(body: BulkDeleteBody, _: dict = Depends(require_admin)) -> dict:
    """Bulk-delete exclusions by ID list."""
    ids = body.data.get("ids", [])
    affected = sum(1 for eid in ids if exclusion_repo.delete(eid))
    return {"data": {"affected": affected}}


@router.delete("/exclusions/{exclusion_id}")
def delete_exclusion(exclusion_id: str, _: dict = Depends(require_admin)) -> dict:
    """Delete an exclusion by ID."""
    return exclusion_commands.delete_exclusion(exclusion_id)


@router.get("/restrictions")
def list_blocklist(
    siteIds: str = Query(None),
    types: str = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a filtered, paginated list of hash blocklist entries."""
    params = {k: v for k, v in locals().items() if v is not None and k not in ("cursor", "limit")}
    records = blocklist_repo.list_all()
    filtered = apply_filters(records, params, _BLOCKLIST_SPECS)
    page, next_cursor, total = paginate(filtered, cursor, limit, RESTRICTION_CURSOR)
    stripped = [{k: v for k, v in r.items() if k not in _BLOCKLIST_INTERNAL} for r in page]
    return build_list_response(stripped, next_cursor, total)


@router.post("/restrictions")
def create_blocklist_entry(body: dict, current_user: dict = Depends(require_admin)) -> dict:
    """Add a hash to the blocklist (restrictions).

    Accepts both flat and wrapped (``{"data": {...}}``) payloads per real S1 API.
    """
    data = body.get("data") or body
    now = utc_now()
    bid = new_id()
    record = {
        "id": bid,
        "value": data.get("value", ""),
        "sha256Value": data.get("sha256Value") or data.get("value", ""),
        "type": data.get("type", "black_hash"),
        "description": data.get("description", ""),
        "source": data.get("source", "user"),
        "osType": data.get("osType", "windows"),
        "scope": data.get("scope") or {
            "siteIds": [], "groupIds": [], "accountIds": [], "tenant": False
        },
        "scopeName": data.get("scopeName", ""),
        "scopePath": data.get("scopePath", ""),
        "siteId": data.get("siteId"),
        "imported": False,
        "includeChildren": data.get("includeChildren", True),
        "includeParents": data.get("includeParents", True),
        "notRecommended": False,
        "userId": current_user.get("userId"),
        "createdAt": now,
        "updatedAt": now,
    }
    blocklist_repo.save_raw(bid, record)
    return build_single_response(record)


@router.delete("/restrictions")
def bulk_delete_blocklist_entries(body: BulkDeleteBody, _: dict = Depends(require_admin)) -> dict:
    """Bulk-delete blocklist entries by ID list."""
    ids = body.data.get("ids", [])
    affected = sum(1 for bid in ids if blocklist_repo.delete(bid))
    return {"data": {"affected": affected}}


@router.delete("/restrictions/{entry_id}")
def delete_blocklist_entry(entry_id: str, _: dict = Depends(require_admin)) -> dict:
    """Remove a hash from the blocklist by path param.

    Implements DELETE /restrictions/{id} (same as real SentinelOne API).
    """
    deleted = blocklist_repo.delete(entry_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Blocklist entry not found")
    return {"data": {"success": True}}
