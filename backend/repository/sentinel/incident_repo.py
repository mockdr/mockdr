"""Repository for Microsoft Sentinel incident entities."""
from __future__ import annotations

from domain.sentinel.incident import SentinelIncident
from repository.base import Repository


class SentinelIncidentRepository(Repository[SentinelIncident]):
    """In-memory repository for ``SentinelIncident`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the sentinel_incidents collection."""
        super().__init__("sentinel_incidents")

    def get_by_number(self, number: int) -> SentinelIncident | None:
        """Return the incident with the given incident number, or None."""
        return next(
            (i for i in self.list_all() if i.incident_number == number), None
        )



sentinel_incident_repo = SentinelIncidentRepository()
