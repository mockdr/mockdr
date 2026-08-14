"""Sentinel threat intelligence query handlers (read-only)."""
from __future__ import annotations

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
        "externalReferences": ind.external_references,
        "validFrom": ind.valid_from,
        "validUntil": ind.valid_until,
        "created": ind.created,
        "lastUpdatedTimeUtc": ind.last_updated,
        "revoked": ind.revoked,
    }, etag=ind.etag)


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
    min_confidence: int = 0,
    max_confidence: int = 100,
    sort_by: str = "",
    page_size: int = 50,
) -> dict:
    """Query indicators with filters."""
    all_inds = sentinel_threat_indicator_repo.list_all()

    filtered = all_inds
    if keywords:
        kw = keywords.lower()
        filtered = [
            i for i in filtered
            if kw in i.display_name.lower() or kw in i.description.lower()
        ]
    if pattern_types:
        filtered = [i for i in filtered if i.pattern_type in pattern_types]
    if threat_types:
        filtered = [i for i in filtered if any(t in i.threat_types for t in threat_types)]
    if sources:
        filtered = [i for i in filtered if i.source in sources]
    filtered = [i for i in filtered if min_confidence <= i.confidence <= max_confidence]

    items = [_indicator_to_arm(i) for i in filtered[:page_size]]
    return build_arm_list(items)


def get_metrics() -> dict:
    """Get TI metrics summary."""
    all_inds = sentinel_threat_indicator_repo.list_all()
    by_type: dict[str, int] = {}
    by_source: dict[str, int] = {}
    for ind in all_inds:
        by_type[ind.pattern_type] = by_type.get(ind.pattern_type, 0) + 1
        by_source[ind.source] = by_source.get(ind.source, 0) + 1
    return {
        "properties": {
            "patternTypeMetrics": [{"patternType": k, "value": v} for k, v in by_type.items()],
            "sourceMetrics": [{"source": k, "value": v} for k, v in by_source.items()],
            "lastUpdatedTimeUtc": "",
        },
    }
