"""Repository for Microsoft Graph Service Principal entities."""
from domain.graph.service_principal import GraphServicePrincipal
from repository.base import Repository


class GraphServicePrincipalRepository(Repository[GraphServicePrincipal]):
    """In-memory repository for ``GraphServicePrincipal`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_service_principals collection."""
        super().__init__("graph_service_principals")


graph_service_principal_repo = GraphServicePrincipalRepository()
