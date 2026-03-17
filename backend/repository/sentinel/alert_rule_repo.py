"""Repository for Microsoft Sentinel alert rule entities."""
from __future__ import annotations

from domain.sentinel.alert_rule import SentinelAlertRule
from repository.base import Repository


class SentinelAlertRuleRepository(Repository[SentinelAlertRule]):
    """In-memory repository for ``SentinelAlertRule`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the sentinel_alert_rules collection."""
        super().__init__("sentinel_alert_rules")



sentinel_alert_rule_repo = SentinelAlertRuleRepository()
