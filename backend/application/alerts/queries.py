
from repository.alert_repo import alert_repo
from utils.filtering import FilterSpec, apply_filters, apply_query_options
from utils.pagination import ALERT_CURSOR, build_list_response, build_single_response, paginate
from utils.serde import record_dict

FILTER_SPECS = [
    FilterSpec("ids", "alertInfo.alertId", "in"),
    FilterSpec("accountIds", "agentDetectionInfo.accountId", "in"),
    FilterSpec("siteIds", "agentDetectionInfo.siteId", "in"),
    FilterSpec("agentIds", "agentRealtimeInfo.id", "in"),
    FilterSpec("severities", "ruleInfo.severity", "in"),
    # The names and spellings the 2.1 swagger declares. SentinelOne takes the
    # enum form in a filter (`UNRESOLVED`) and answers the readable one
    # (`Unresolved`); a client written against the docs sent the documented
    # name, the mock declared only its own plural, and the filter was dropped
    # — a 200 with everything in it.
    FilterSpec("severity", "ruleInfo.severity", "in", enum=True),
    FilterSpec("analystVerdict", "alertInfo.analystVerdict", "in", enum=True),
    FilterSpec("incidentStatus", "alertInfo.incidentStatus", "in", enum=True),
    FilterSpec("categories", "ruleInfo.treatAsThreat", "in"),
    FilterSpec("groupIds", "agentRealtimeInfo.groupId", "in"),
    FilterSpec("analystVerdicts", "alertInfo.analystVerdict", "in", enum=True),
    FilterSpec("incidentStatuses", "alertInfo.incidentStatus", "in", enum=True),
    FilterSpec("query", "ruleInfo.name|ruleInfo.description", "full_text"),
    FilterSpec("createdAt__gte", "alertInfo.createdAt", "gte_dt"),
    FilterSpec("createdAt__lte", "alertInfo.createdAt", "lte_dt"),
]


def list_alerts(params: dict, cursor: str | None, limit: int) -> dict:
    """Return a filtered, paginated list of alerts sorted by creation date."""
    records = [record_dict(a) for a in alert_repo.list_all()]
    filtered = apply_filters(records, params, FILTER_SPECS)
    filtered.sort(key=lambda r: (r.get("alertInfo") or {}).get("createdAt", ""), reverse=True)
    filtered = apply_query_options(filtered, params)
    page, next_cursor, total = paginate(filtered, cursor, limit, ALERT_CURSOR)
    return build_list_response(
        page,
        next_cursor,
        total,
        definition="v2_1.alerts.schemas_AlertInformationSchema_many_200",
        strict=True,
    )


def get_alert(alert_id: str) -> dict | None:
    """Return a single alert by ID, or None if not found."""
    alert = alert_repo.get(alert_id)
    if not alert:
        return None
    return build_single_response(record_dict(alert))
