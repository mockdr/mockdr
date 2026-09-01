
from application.documented_filters import DOCUMENTED_FILTERS
from repository.threat_repo import threat_repo
from utils.filtering import (
    FilterSpec,
    apply_filters,
    apply_query_options,
    reject_wrong_type,
)
from utils.nested import get_nested
from utils.pagination import THREAT_CURSOR, build_list_response, paginate
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


def get_threat_timeline(threat_id: str) -> dict | None:
    """Return the timeline events for the given threat, or None if not found."""
    threat = threat_repo.get(threat_id)
    if not threat:
        return None
    return build_list_response(
        threat.timeline,
        None,
        len(threat.timeline),
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


def get_threat_notes(threat_id: str) -> dict | None:
    """Return the analyst notes for the given threat, or None if not found."""
    threat = threat_repo.get(threat_id)
    if not threat:
        return None
    return build_list_response(
        threat.notes,
        None,
        len(threat.notes),
        definition="threats.schemas_ThreatNoteSchema_many_200",
    )
