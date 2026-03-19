"""Repository for Microsoft Graph Detected App entities."""
from domain.graph.detected_app import GraphDetectedApp
from repository.base import Repository


class GraphDetectedAppRepository(Repository[GraphDetectedApp]):
    """In-memory repository for ``GraphDetectedApp`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_detected_apps collection."""
        super().__init__("graph_detected_apps")


graph_detected_app_repo = GraphDetectedAppRepository()
