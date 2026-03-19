"""Repository for Microsoft Graph Service Health entities."""
from domain.graph.service_health import GraphServiceHealth
from repository.base import Repository


class GraphServiceHealthRepository(Repository[GraphServiceHealth]):
    """In-memory repository for ``GraphServiceHealth`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_service_health collection."""
        super().__init__("graph_service_health")


graph_service_health_repo = GraphServiceHealthRepository()
