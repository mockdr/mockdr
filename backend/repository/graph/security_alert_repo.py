"""Repository for Microsoft Graph Security Alert v2 entities."""
from domain.graph.security_alert import GraphSecurityAlert
from repository.base import Repository


class GraphSecurityAlertRepository(Repository[GraphSecurityAlert]):
    """In-memory repository for ``GraphSecurityAlert`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_security_alerts collection."""
        super().__init__("graph_security_alerts")


graph_security_alert_repo = GraphSecurityAlertRepository()
