"""Repository for Microsoft Graph Security Incident entities."""
from domain.graph.security_incident import GraphSecurityIncident
from repository.base import Repository


class GraphSecurityIncidentRepository(Repository[GraphSecurityIncident]):
    """In-memory repository for ``GraphSecurityIncident`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_security_incidents collection."""
        super().__init__("graph_security_incidents")


graph_security_incident_repo = GraphSecurityIncidentRepository()
