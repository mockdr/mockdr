from dataclasses import asdict

from repository.threat_repo import threat_repo
from utils.filtering import FilterSpec, apply_filters
from utils.pagination import THREAT_CURSOR, build_list_response, build_single_response, paginate
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
    FilterSpec("resolved", "threatInfo.resolved", "bool"),
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


def list_threats(params: dict, cursor: str | None, limit: int) -> dict:
    """Return a filtered, paginated list of threats sorted by creation date."""
    records = [asdict(t) for t in threat_repo.list_all()]
    filtered = apply_filters(records, params, FILTER_SPECS)
    filtered.sort(key=lambda r: (r.get("threatInfo") or {}).get("createdAt", ""), reverse=True)
    page, next_cursor, total = paginate(filtered, cursor, limit, THREAT_CURSOR)
    return build_list_response([strip_fields(r, _INTERNAL) for r in page], next_cursor, total)


def get_threat(threat_id: str) -> dict | None:
    """Return a single threat by ID with internal fields stripped, or None."""
    threat = threat_repo.get(threat_id)
    if not threat:
        return None
    return build_single_response(strip_fields(asdict(threat), _INTERNAL))


def get_threat_timeline(threat_id: str) -> dict | None:
    """Return the timeline events for the given threat, or None if not found."""
    threat = threat_repo.get(threat_id)
    if not threat:
        return None
    return build_list_response(threat.timeline, None, len(threat.timeline))


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
    return build_list_response(threat.notes, None, len(threat.notes))
