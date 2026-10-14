
from application.documented_filters import DOCUMENTED_FILTERS
from config import DEFAULT_PAGE_SIZE
from repository.threat_repo import threat_repo
from utils.filtering import (
    FilterSpec,
    apply_filters,
    apply_query_options,
    reject_wrong_type,
)
from utils.nested import get_nested
from utils.pagination import (
    THREAT_CURSOR,
    build_list_response,
    paginate,
)
from utils.serde import record_dict
from utils.strip import strip_fields

# Internal fields stored on Threat but never returned in list/get responses
_INTERNAL: frozenset[str] = frozenset({"notes", "timeline", "_fetched_file"})

FILTER_SPECS = [
    FilterSpec("ids", "id", "in"),
    FilterSpec("accountIds", "agentDetectionInfo.accountId", "in"),
    FilterSpec("siteIds", "agentDetectionInfo.siteId", "in"),
    FilterSpec("groupIds", "agentDetectionInfo.groupId", "in"),
    FilterSpec("agentIds", "agentRealtimeInfo.agentId", "in"),
    FilterSpec("classifications", "threatInfo.classification", "in"),
    FilterSpec("mitigationStatuses", "threatInfo.mitigationStatus", "in"),
    FilterSpec("analystVerdicts", "threatInfo.analystVerdict", "in"),
    FilterSpec("incidentStatuses", "threatInfo.incidentStatus", "in"),
    FilterSpec("confidenceLevels", "threatInfo.confidenceLevel", "in"),
    FilterSpec("contentHashes", "threatInfo.sha1", "in"),
    FilterSpec("threatName", "threatInfo.threatName", "contains"),
    FilterSpec(
        "query",
        "threatInfo.threatName|threatInfo.fileName|agentDetectionInfo.agentComputerName",
        "full_text",
    ),
    FilterSpec("createdAt__gte", "threatInfo.createdAt", "gte_dt"),
    FilterSpec("createdAt__lte", "threatInfo.createdAt", "lte_dt"),
]


def public_threat(record: dict) -> dict:
    """The record as the API lists it.

    Internal fields and the undeclared ``agentDetectionInfo.agentComputerName``
    are removed.
    """
    record = strip_fields(record, _INTERNAL)
    info = record.get("agentDetectionInfo")
    if isinstance(info, dict) and "agentComputerName" in info:
        record = {
            **record,
            "agentDetectionInfo": {k: v for k, v in info.items() if k != "agentComputerName"},
        }
    return record


#: The incident statuses `?resolved=false` stands for. The swagger calls
#: `resolved` a spelling kept "for backward-compatibility with API 2.0" — it
#: is the same state under an older name, not a field of its own, and the
#: threat schema declares no `threatInfo.resolved` to read it off. Pointed at
#: one, the documented filter answered `resolved=true` with nothing while six
#: threats were resolved.
_UNRESOLVED_STATUSES = ("unresolved", "in_progress")


def _as_incident_status(params: dict) -> dict:
    """`?resolved=` rewritten as the incident statuses it means.

    The swagger types it `boolean`, and a value that type cannot hold is
    refused here the way every other typed filter is refused — through the
    same helper, so the envelope comes from the one handler measured against
    the vendor. `?resolved=maybe` used to be read as false and answered 200
    with every unresolved threat.
    """
    raw = params.get("resolved")
    if raw is None or raw == "" or "incidentStatuses" in params:
        # An empty value has always meant "unset" on this mount, and still
        # does — it is not a boolean the type cannot hold.
        return {k: v for k, v in params.items() if k != "resolved"}
    reject_wrong_type("resolved", "boolean", raw)
    wanted = str(raw).strip().lower() in ("true", "1", "yes")
    rest = {k: v for k, v in params.items() if k != "resolved"}
    rest["incidentStatuses"] = (
        "resolved" if wanted else ",".join(_UNRESOLVED_STATUSES))
    return rest


class UnselectableFilterError(ValueError):
    """A threat action's filter names a member this mock cannot select on."""


#: Members of a threat action's filter that select nothing by design: the
#: list route declares `tenant` and answers the same set with it (mockdr
#: seeds one tenant), so an action does too.
_NO_OP_FILTER_MEMBERS = frozenset({"tenant"})


def resolve_threat_ids(filter_obj: dict | None, *, empty_selects_all: bool) -> list[str]:
    """The threats a bulk action's ``filter`` selects — all of it, not just ``ids``.

    The swagger's request schemas for the threat actions
    (``threats.schemas_ThreatsMitigateRequestSchema``,
    ``ThreatsAnalystVerdictSchema``, ``ThreatsIncidentSchema``, …) declare
    the same ninety-nine filter members as ``GET /threats`` — ``agentIds``,
    ``siteIds``, ``resolved``, ``contentHashes`` among them. The actions read
    ``filter.ids`` and nothing else, so a mitigation scoped to one agent's
    threats matched nothing and answered ``{"affected": 0}`` with a 200. The
    filter now goes through the engine the list route uses, so an action
    selects exactly what a GET with those parameters lists.

    A member this mock has no filter for is refused, as the agent actions
    refuse it: ignoring it would widen the selection to everything the other
    members match. An empty filter selects every threat where the swagger
    says so ("You can also leave this field empty to apply to all available
    threats" — mitigate, add-to-blacklist, fetch-file) and nothing
    elsewhere, which is what the mock always did and nothing documents
    otherwise.

    Raises:
        UnselectableFilterError: The filter names a member the mock cannot
            select on.
    """
    params = {k: v for k, v in (filter_obj or {}).items() if v is not None}
    if not params:
        return [t.id for t in threat_repo.list_all()] if empty_selects_all else []
    specs = FILTER_SPECS + DOCUMENTED_FILTERS.get("/threats", [])
    known = {spec.param for spec in specs} | {"resolved"} | _NO_OP_FILTER_MEMBERS
    unknown = sorted(set(params) - known)
    if unknown:
        msg = (
            f"The filter names {'members' if len(unknown) > 1 else 'a member'} "
            f"this endpoint cannot select on: {', '.join(unknown)}."
        )
        raise UnselectableFilterError(msg)
    params = _as_incident_status(
        {k: v for k, v in params.items() if k not in _NO_OP_FILTER_MEMBERS})
    matched = apply_filters(threat_repo.list_all(), params, specs)
    return [str(t.id) for t in matched]


def list_threats(params: dict, cursor: str | None, limit: int) -> dict:
    """Return a filtered, paginated list of threats sorted by creation date."""
    params = _as_incident_status(params)
    # Filtered and sorted on the stored records; only the page becomes dicts.
    filtered = apply_filters(
        threat_repo.list_all(),
        params,
        FILTER_SPECS + DOCUMENTED_FILTERS.get("/threats", []),
    )
    filtered.sort(key=lambda t: get_nested(t, "threatInfo.createdAt") or "", reverse=True)
    filtered = apply_query_options(
        filtered, params, FILTER_SPECS + DOCUMENTED_FILTERS.get("/threats", []))
    page, next_cursor, total = paginate(filtered, cursor, limit, THREAT_CURSOR)
    return build_list_response(
        [public_threat(record_dict(t)) for t in page],
        next_cursor,
        total,
        definition="threats.schemas_ThreatSchema_many_200",
    )


def get_threat_timeline(
    threat_id: str, skip: int = 0, cursor: str | None = None,
    limit: int = DEFAULT_PAGE_SIZE,
) -> dict | None:
    """Return a page of the timeline for the given threat, or None if not found.

    Args:
        threat_id: The threat whose timeline this is.
        skip:      Documented offset, applied before the cursor.
        cursor:    Opaque cursor from the previous answer.
        limit:     Page size.

    Returns:
        The S1 list envelope, or None when no such threat exists.
    """
    threat = threat_repo.get(threat_id)
    if not threat:
        return None
    events = threat.timeline[skip:]
    page, next_cursor, total = paginate(events, cursor, limit)
    return build_list_response(
        page,
        next_cursor,
        total,
        definition="threat_analysis.schemas_TimelineViewSchema_many_200",
        strict=True,
    )


def get_fetched_file(threat_id: str) -> tuple[bytes, str] | None:
    """Return the fetched file bytes and filename for a threat, or None.

    Returns a tuple of (zip_bytes, filename) if a file was fetched,
    or None if the threat doesn't exist or no file has been fetched yet.
    """
    threat = threat_repo.get(threat_id)
    if not threat or not threat._fetched_file:
        return None
    file_name = threat.threatInfo.get("fileName", "sample.exe")
    return threat._fetched_file, f"{file_name}.zip"


def get_threat_notes(
    threat_id: str, skip: int = 0, cursor: str | None = None,
    limit: int = DEFAULT_PAGE_SIZE,
) -> dict | None:
    """Return a page of the analyst notes for a threat, or None if not found.

    Args:
        threat_id: The threat whose notes these are.
        skip:      Documented offset, applied before the cursor.
        cursor:    Opaque cursor from the previous answer.
        limit:     Page size.

    Returns:
        The S1 list envelope, or None when no such threat exists.
    """
    threat = threat_repo.get(threat_id)
    if not threat:
        return None
    notes = threat.notes[skip:]
    page, next_cursor, total = paginate(notes, cursor, limit)
    return build_list_response(
        page,
        next_cursor,
        total,
        definition="threats.schemas_ThreatNoteSchema_many_200",
    )
