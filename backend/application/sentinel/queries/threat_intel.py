"""Sentinel threat intelligence query handlers (read-only)."""
from __future__ import annotations

from collections.abc import Callable

from domain.sentinel.threat_indicator import SentinelThreatIndicator
from repository.sentinel.threat_indicator_repo import sentinel_threat_indicator_repo
from utils.sentinel.pagination import build_next_link, parse_skip_token
from utils.sentinel.response import build_arm_list, build_arm_resource


def _indicator_to_arm(ind: SentinelThreatIndicator) -> dict:
    """Convert a SentinelThreatIndicator to ARM format."""
    return build_arm_resource("threatIntelligence/main/indicators", ind.name, {
        "displayName": ind.display_name,
        "description": ind.description,
        "pattern": ind.pattern,
        "patternType": ind.pattern_type,
        "source": ind.source,
        "confidence": ind.confidence,
        "threatTypes": ind.threat_types,
        "killChainPhases": ind.kill_chain_phases,
        "labels": ind.labels,
        "threatIntelligenceTags": ind.threat_intelligence_tags,
        "externalReferences": ind.external_references,
        "validFrom": ind.valid_from,
        "validUntil": ind.valid_until,
        "created": ind.created,
        "lastUpdatedTimeUtc": ind.last_updated,
        "revoked": ind.revoked,
    }, etag=ind.etag, kind="indicator")


def list_indicators(top: int = 50, skip_token: str = "", request_url: str = "") -> dict:
    """List all TI indicators.

    Args:
        top:         Maximum results.
        skip_token:  Pagination token (offset-based).
        request_url: Full request URL, used to build an absolute ``nextLink``.

    Returns:
        ARM list response dict.

    Raises:
        HTTPException: 400 if the skip token was not issued by this service.
    """
    all_inds = sentinel_threat_indicator_repo.list_all()
    offset = parse_skip_token(skip_token)
    page = all_inds[offset:offset + top]
    items = [_indicator_to_arm(i) for i in page]
    next_link = (
        build_next_link(request_url, offset + top) if offset + top < len(all_inds) else ""
    )
    return build_arm_list(items, next_link=next_link)


def get_indicator(name: str) -> dict | None:
    """Get a single TI indicator."""
    ind = sentinel_threat_indicator_repo.get(name)
    if not ind:
        return None
    return _indicator_to_arm(ind)


def query_indicators(
    keywords: str = "",
    pattern_types: list[str] | None = None,
    threat_types: list[str] | None = None,
    sources: list[str] | None = None,
    ids: list[str] | None = None,
    min_confidence: int = 0,
    max_confidence: int = 100,
    include_disabled: bool = True,
    sort_by: list[dict] | None = None,
    page_size: int = 50,
) -> dict:
    """Query indicators with the criteria the ARM body carries.

    Every member of ``ThreatIntelligenceFilteringCriteria`` the spec
    documents is read here. Five of them — the threat types, the confidence
    bounds, the ids, the sort and the page size — were taken by the query
    and never used, so a client narrowing a hunt to two indicators got the
    whole feed back in whatever order the repository held it.
    """
    filtered = list(sentinel_threat_indicator_repo.list_all())
    if keywords:
        keyword = keywords.lower()
        filtered = [
            i for i in filtered
            if keyword in i.display_name.lower() or keyword in i.description.lower()
        ]
    if pattern_types:
        filtered = [i for i in filtered if i.pattern_type in pattern_types]
    if threat_types:
        filtered = [i for i in filtered if any(t in i.threat_types for t in threat_types)]
    if sources:
        filtered = [i for i in filtered if i.source in sources]
    if ids:
        wanted = set(ids)
        filtered = [i for i in filtered if i.name in wanted]
    if not include_disabled:
        filtered = [i for i in filtered if not getattr(i, "disabled", False)]
    filtered = [i for i in filtered if min_confidence <= i.confidence <= max_confidence]

    for criterion in reversed(sort_by or []):
        order = str(criterion.get("sortOrder", "")).lower()
        if order not in ("ascending", "descending"):
            # `unsorted` — and anything else — leaves the order alone.
            continue
        key = str(criterion.get("itemKey", ""))
        filtered.sort(key=_sorter(key), reverse=order == "descending")

    items = [_indicator_to_arm(i) for i in filtered[:page_size]]
    return build_arm_list(items)


def _sorter(key: str) -> Callable[[object], tuple[int, float, str]]:
    """A sort key that reads one attribute off an indicator."""
    return lambda indicator: _sort_value(getattr(indicator, key, None))


def _sort_value(value: object) -> tuple[int, float, str]:
    """Order numbers numerically, text lexically, and absent values last."""
    if value is None or value == "":
        return (2, 0.0, "")
    try:
        return (0, float(value), "")  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return (1, 0.0, str(value))


def _metric_entities(counts: dict[str, int]) -> list[dict]:
    """`ThreatIntelligenceMetricEntity`: a name and a count, both named so."""
    return [{"metricName": name, "metricValue": value}
            for name, value in sorted(counts.items())]


def get_metrics() -> dict:
    """Get TI metrics summary.

    `ThreatIntelligenceMetricsList` is a *list*: `{"value": [{"properties":
    {...}}]}`.  mockdr answered the properties object alone, and named the
    entries `patternType`/`source` and `value` where the swagger names every
    one of them `metricName` and `metricValue` — so a client reading
    `value[0].properties.patternTypeMetrics[0].metricName` found nothing at
    any level.  `threatTypeMetrics` was absent altogether (2024-03-01
    SecurityInsights swagger, `ThreatIntelligence.json`).
    """
    all_inds = sentinel_threat_indicator_repo.list_all()
    by_type: dict[str, int] = {}
    by_source: dict[str, int] = {}
    by_threat: dict[str, int] = {}
    last_updated = ""
    for ind in all_inds:
        by_type[ind.pattern_type] = by_type.get(ind.pattern_type, 0) + 1
        by_source[ind.source] = by_source.get(ind.source, 0) + 1
        for threat_type in ind.threat_types:
            by_threat[threat_type] = by_threat.get(threat_type, 0) + 1
        last_updated = max(last_updated, ind.last_updated or "")
    return {
        "value": [{
            "properties": {
                "lastUpdatedTimeUtc": last_updated,
                "threatTypeMetrics": _metric_entities(by_threat),
                "patternTypeMetrics": _metric_entities(by_type),
                "sourceMetrics": _metric_entities(by_source),
            },
        }],
    }
