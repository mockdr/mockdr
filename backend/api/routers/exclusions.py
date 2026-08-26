from fastapi import APIRouter, Depends, HTTPException, Query
from starlette.requests import Request

from api.auth import require_admin
from api.dto.requests import BulkDeleteBody
from application.documented_filters import DOCUMENTED_FILTERS
from application.exclusions import commands as exclusion_commands
from application.exclusions import queries as exclusion_queries
from config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from repository.blocklist_repo import blocklist_repo
from repository.exclusion_repo import exclusion_repo
from utils.documented_params import documented_openapi, documented_params
from utils.dt import utc_now
from utils.filtering import FilterSpec, apply_filters, apply_query_options
from utils.id_gen import new_id
from utils.pagination import (
    RESTRICTION_CURSOR,
    build_list_response,
    build_single_response,
    paginate,
)
from utils.s1_fixtures import restrict_s1
from utils.vendor_errors import build_vendor_error

router = APIRouter(tags=["Exclusions & Blocklist"])

_BLOCKLIST_SPECS = [
    FilterSpec("siteIds", "siteId", "in"),
    FilterSpec("types", "type", "in"),
]

_BLOCKLIST_INTERNAL = {"siteId"}

#: What the 2.1 swagger requires inside `data` on both update routes. The
#: record to change is named in the body, not in the path — this is how a
#: real client updates an exclusion or a blocklist entry.
_UPDATE_REQUIRED = ("id", "osType", "type")

#: The blocklist fields an update may set. `id` names the record and
#: `hashId`, `userId`, `createdAt` and the scope belong to the service.
_RESTRICTION_UPDATABLE = ("description", "osType", "source", "value", "sha256Value", "type")


def _update_payload(body: dict) -> dict:
    """The `data` object of an update body, refused if it is not complete."""
    data = body.get("data")
    if not isinstance(data, dict):
        raise HTTPException(
            status_code=400,
            detail=build_vendor_error("sentinelone", 400, "data is required"),
        )
    missing = [name for name in _UPDATE_REQUIRED if not data.get(name)]
    if missing:
        raise HTTPException(
            status_code=400,
            detail=build_vendor_error(
                "sentinelone", 400, f"data.{missing[0]} is required"),
        )
    return data


@router.get("/exclusions", openapi_extra=documented_openapi("/exclusions"))
def list_exclusions(
    request: Request,
    ids: str = Query(None),
    # `tenant=true` asks for the whole tenant rather than the caller's own
    # scope. mockdr seeds one tenant, and the account scoping a non-admin
    # token carries still applies, so the answer is the same set — but the
    # parameter is declared rather than silently dropped.
    tenant: bool = Query(None),
    siteIds: str = Query(None),
    type: str = Query(None),
    types: str = Query(None),
    osTypes: str = Query(None),
    value__contains: str = Query(None),
    includeChildren: bool = Query(None),
    includeParents: bool = Query(None),
    sortBy: str = Query(None),
    sortOrder: str = Query(None),
    skip: int = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a filtered, paginated list of threat exclusions.

    Accepts both ``type`` (singular) and ``types`` (plural) query parameters.
    """
    params = {
        k: v for k, v in locals().items()
        if v is not None and k not in ("cursor", "limit", "request")
    }
    params.update(documented_params(request, "/exclusions"))
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
    try:
        return exclusion_commands.create_exclusion(body, current_user.get("userId"))
    except exclusion_commands.InvalidExclusionError as exc:
        raise HTTPException(
            status_code=400,
            detail=build_vendor_error("sentinelone", 400, str(exc)),
        ) from exc


@router.put("/exclusions")
def update_exclusion_by_body(body: dict, current_user: dict = Depends(require_admin)) -> dict:
    """Update the exclusion named by ``data.id``.

    The 2.1 API updates by body here, and answers the list shape rather than
    the single one — mockdr served the by-id path it invented and answered
    405 to the call a real client makes.
    """
    data = _update_payload(body)
    result = exclusion_commands.update_exclusion(
        str(data["id"]), {"data": data}, current_user.get("userId"),
    )
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_vendor_error("sentinelone", 404, "Exclusion not found"),
        )
    return restrict_s1(
        {"data": [result["data"]]}, "exclusions.schemas_ExclusionSchema_many_200",
    )


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


@router.get("/restrictions", openapi_extra=documented_openapi("/restrictions"))
def list_blocklist(
    request: Request,
    siteIds: str = Query(None),
    # See the note on the exclusions handler above.
    tenant: bool = Query(None),
    types: str = Query(None),
    sortBy: str = Query(None),
    sortOrder: str = Query(None),
    skip: int = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a filtered, paginated list of hash blocklist entries."""
    params = {
        k: v for k, v in locals().items()
        if v is not None and k not in ("cursor", "limit", "request")
    }
    params.update(documented_params(request, "/restrictions"))
    records = blocklist_repo.list_all()
    filtered = apply_filters(
        records, params, _BLOCKLIST_SPECS + DOCUMENTED_FILTERS.get("/restrictions", []),
    )
    filtered = apply_query_options(filtered, params)
    page, next_cursor, total = paginate(filtered, cursor, limit, RESTRICTION_CURSOR)
    stripped = [{k: v for k, v in r.items() if k not in _BLOCKLIST_INTERNAL} for r in page]
    return build_list_response(
        stripped, next_cursor, total, definition="exclusions.schemas_RestrictionSchemaGet_many_200"
    )


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
        "scope": data.get("scope")
        or {"siteIds": [], "groupIds": [], "accountIds": [], "tenant": False},
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


@router.put("/restrictions")
def update_blocklist_entry(body: dict, _: dict = Depends(require_admin)) -> dict:
    """Update the blocklist entry named by ``data.id``."""
    data = _update_payload(body)
    entry_id = str(data["id"])
    record = blocklist_repo.get(entry_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=build_vendor_error("sentinelone", 404, "Blocklist entry not found"),
        )
    updated = dict(record)
    for key in _RESTRICTION_UPDATABLE:
        if key in data:
            updated[key] = data[key]
    updated["updatedAt"] = utc_now()
    blocklist_repo.save_raw(entry_id, updated)
    return restrict_s1(
        {"data": [updated]}, "exclusions.schemas_RestrictionSchema_many_200",
    )


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
