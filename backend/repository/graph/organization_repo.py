"""Repository for Microsoft Graph Organization entities."""
from domain.graph.organization import GraphOrganization
from repository.base import Repository


class GraphOrganizationRepository(Repository[GraphOrganization]):
    """In-memory repository for ``GraphOrganization`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_organization collection."""
        super().__init__("graph_organization")


graph_organization_repo = GraphOrganizationRepository()
