"""Repository for Microsoft Sentinel alert entities."""
from __future__ import annotations

from domain.sentinel.alert import SentinelAlert
from repository.base import Repository


class SentinelAlertRepository(Repository[SentinelAlert]):
    """In-memory repository for ``SentinelAlert`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the sentinel_alerts collection."""
        super().__init__("sentinel_alerts")

    def get_by_incident_id(self, incident_id: str) -> list[SentinelAlert]:
        """Return all alerts associated with the given incident."""
        return [a for a in self.list_all() if a.incident_id == incident_id]



sentinel_alert_repo = SentinelAlertRepository()
