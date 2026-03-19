"""Repository for Microsoft Graph Risky User entities."""
from domain.graph.risky_user import GraphRiskyUser
from repository.base import Repository


class GraphRiskyUserRepository(Repository[GraphRiskyUser]):
    """In-memory repository for ``GraphRiskyUser`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_risky_users collection."""
        super().__init__("graph_risky_users")


graph_risky_user_repo = GraphRiskyUserRepository()
