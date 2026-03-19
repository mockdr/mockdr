"""Repository for Palo Alto Cortex XDR Incident entities."""
from domain.xdr_incident import XdrIncident
from repository.base import Repository


class XdrIncidentRepository(Repository[XdrIncident]):
    """In-memory repository for ``XdrIncident`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the xdr_incidents collection."""
        super().__init__("xdr_incidents")


xdr_incident_repo = XdrIncidentRepository()
