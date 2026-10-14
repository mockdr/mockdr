
from application.documented_filters import DOCUMENTED_FILTERS
from repository.agent_repo import agent_repo
from repository.alert_repo import alert_repo
from utils.filter_selection import select_ids
from utils.filtering import FilterSpec, apply_filters, apply_query_options
from utils.nested import get_nested
from utils.pagination import ALERT_CURSOR, build_list_response, paginate
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
    # Sent by the XSOAR SentinelOne V2 integration, declared by the swagger,
    # and dropped here until now: the OS the alert's agent runs, and a
    # substring of the rule's name.
    FilterSpec("osType", "agentDetectionInfo.osFamily", "in", enum=True),
    FilterSpec("ruleName__contains", "ruleInfo.name", "contains"),
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
    filtered = apply_filters(
        alert_repo.list_all(),
        params,
        FILTER_SPECS + DOCUMENTED_FILTERS.get("/cloud-detection/alerts", []),
    )
    filtered.sort(key=lambda a: get_nested(a, "alertInfo.createdAt") or "", reverse=True)
    filtered = apply_query_options(filtered, params)
    page, next_cursor, total = paginate(filtered, cursor, limit, ALERT_CURSOR)
    records = [record_dict(a) for a in page]
    response = build_list_response(
        records,
        next_cursor,
        total,
        definition="v2_1.alerts.schemas_AlertInformationSchema_many_200",
        strict=True,
    )
    for item, record in zip(response["data"], records, strict=True):
        item["agentRealtimeInfo"] = _agent_realtime_info(record)
    return response


def _agent_realtime_info(record: dict) -> dict:
    """The alert's agent as it is now, in the members real replies carry.

    The 2.1 swagger's AlertInformationSchema has no ``agentRealtimeInfo``,
    so the strict shaping above dropped it -- and XSOAR's SentinelOne-V2
    reads it unguarded (``get_alerts``: ``agent_realtime_info.get("name")``),
    so ``sentinelone-get-alerts`` raised AttributeError on every page.
    Recorded replies of ``/cloud-detection/alerts`` carry it with exactly
    these members: demisto/content's SentinelOneEventCollector
    ``test_data/alerts.json`` and the captures in elastic/integrations'
    ``sentinel_one`` alert pipeline tests (``id``, ``infected``,
    ``isActive``, ``isDecommissioned``, ``machineType``, ``name``, ``os``,
    ``uuid``).
    """
    stored = record.get("agentRealtimeInfo") or {}
    agent = agent_repo.get(str(stored.get("id") or ""))
    if agent is None:
        return {
            "id": stored.get("id"), "infected": None, "isActive": None,
            "isDecommissioned": None, "machineType": None,
            "name": stored.get("agentComputerName"), "os": stored.get("os"), "uuid": None,
        }
    return {
        "id": agent.id, "infected": agent.infected, "isActive": agent.isActive,
        "isDecommissioned": agent.isDecommissioned, "machineType": agent.machineType,
        "name": agent.computerName, "os": agent.osType, "uuid": agent.uuid,
    }


#: The swagger's own filters for GET /cloud-detection/rules. `status` and
#: `severity` are declared with enums the records already spell that way.
RULE_FILTER_SPECS = [
    FilterSpec("status", "status", "in", enum=True),
    FilterSpec("severity", "severity", "in", enum=True),
    FilterSpec("queryType", "queryType", "in"),
]


def filter_star_rules(params: dict) -> list[dict]:
    """The STAR rules a request asks for; every rule when it asks for none."""
    from repository.store import store  # noqa: PLC0415 - avoids an import cycle

    matched = apply_filters(
        list(store.get_all("star_rules")),
        params,
        RULE_FILTER_SPECS + DOCUMENTED_FILTERS.get("/cloud-detection/rules", []),
    )
    # `sortBy`/`sortOrder`/`skip` are documented on this route like any other.
    return apply_query_options(matched, params)


def select_alert_ids(raw_filter: dict) -> list[str]:
    """The ids of the alerts a write's ``filter`` selects, as the listing would.

    Raises:
        UnselectableFilterError: A member the listing cannot filter on.
    """
    return select_ids(
        alert_repo.list_all(), raw_filter,
        FILTER_SPECS + DOCUMENTED_FILTERS.get("/cloud-detection/alerts", []),
        id_field="alertInfo.alertId",
        no_op_members=("tenant",),
    )
