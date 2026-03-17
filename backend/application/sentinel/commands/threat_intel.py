"""Sentinel threat intelligence indicator command handlers."""
from __future__ import annotations

import re
import uuid

from domain.sentinel.threat_indicator import SentinelThreatIndicator
from repository.sentinel.threat_indicator_repo import sentinel_threat_indicator_repo
from utils.dt import utc_now


def create_or_update_indicator(name: str, properties: dict) -> SentinelThreatIndicator:
    """Create or update a threat intelligence indicator.

    Args:
        name:       Indicator resource name.
        properties: ARM properties bag.

    Returns:
        The created/updated indicator.
    """
    now = utc_now()
    existing = sentinel_threat_indicator_repo.get(name)

    if existing:
        for key in ("displayName", "description", "pattern", "patternType",
                     "source", "confidence", "threatTypes", "labels",
                     "validFrom", "validUntil", "revoked"):
            if key in properties:
                attr = _camel_to_snake(key)
                setattr(existing, attr, properties[key])
        existing.last_updated = now
        existing.etag = uuid.uuid4().hex[:8]
        sentinel_threat_indicator_repo.save(existing)
        return existing

    indicator = SentinelThreatIndicator(
        name=name,
        display_name=properties.get("displayName", name),
        description=properties.get("description", ""),
        pattern=properties.get("pattern", ""),
        pattern_type=properties.get("patternType", ""),
        source=properties.get("source", "MockDR"),
        confidence=properties.get("confidence", 50),
        threat_types=properties.get("threatTypes", []),
        labels=properties.get("labels", []),
        valid_from=properties.get("validFrom", now),
        valid_until=properties.get("validUntil", ""),
        created=now,
        last_updated=now,
        etag=uuid.uuid4().hex[:8],
    )
    sentinel_threat_indicator_repo.save(indicator)
    return indicator


def create_indicator(properties: dict) -> SentinelThreatIndicator:
    """Create a new indicator with auto-generated name."""
    name = f"indicator--{uuid.uuid4()}"
    return create_or_update_indicator(name, properties)


def delete_indicator(name: str) -> bool:
    """Delete a TI indicator."""
    return sentinel_threat_indicator_repo.delete(name)


def append_tags(indicator_ids: list[str], tags: list[str]) -> int:
    """Append tags to indicators."""
    count = 0
    for name in indicator_ids:
        ind = sentinel_threat_indicator_repo.get(name)
        if ind:
            for tag in tags:
                if tag not in ind.labels:
                    ind.labels.append(tag)
            sentinel_threat_indicator_repo.save(ind)
            count += 1
    return count


def replace_tags(indicator_ids: list[str], tags: list[str]) -> int:
    """Replace tags on indicators."""
    count = 0
    for name in indicator_ids:
        ind = sentinel_threat_indicator_repo.get(name)
        if ind:
            ind.labels = list(tags)
            sentinel_threat_indicator_repo.save(ind)
            count += 1
    return count


def _camel_to_snake(name: str) -> str:
    """Convert camelCase to snake_case."""
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()
