"""Repository for Microsoft Graph Mobile App entities."""
from domain.graph.mobile_app import GraphMobileApp
from repository.base import Repository


class GraphMobileAppRepository(Repository[GraphMobileApp]):
    """In-memory repository for ``GraphMobileApp`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_mobile_apps collection."""
        super().__init__("graph_mobile_apps")


graph_mobile_app_repo = GraphMobileAppRepository()
