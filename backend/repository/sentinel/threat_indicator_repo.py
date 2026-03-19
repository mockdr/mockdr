"""Repository for Microsoft Sentinel threat indicator entities."""
from __future__ import annotations

from domain.sentinel.threat_indicator import SentinelThreatIndicator
from repository.base import Repository


class SentinelThreatIndicatorRepository(Repository[SentinelThreatIndicator]):
    """In-memory repository for ``SentinelThreatIndicator`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the sentinel_threat_indicators collection."""
        super().__init__("sentinel_threat_indicators")



sentinel_threat_indicator_repo = SentinelThreatIndicatorRepository()
