"""Repository for Microsoft Graph Application entities."""
from domain.graph.application import GraphApplication
from repository.base import Repository


class GraphApplicationRepository(Repository[GraphApplication]):
    """In-memory repository for ``GraphApplication`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_applications collection."""
        super().__init__("graph_applications")


graph_application_repo = GraphApplicationRepository()
