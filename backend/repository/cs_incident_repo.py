"""Repository for CrowdStrike Falcon Incident entities."""
from domain.cs_incident import CsIncident
from repository.base import Repository


class CsIncidentRepository(Repository[CsIncident]):
    """In-memory repository for ``CsIncident`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the cs_incidents collection."""
        super().__init__("cs_incidents")



cs_incident_repo = CsIncidentRepository()
