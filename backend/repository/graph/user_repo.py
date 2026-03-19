"""Repository for Microsoft Graph User entities."""
from domain.graph.user import GraphUser
from repository.base import Repository


class GraphUserRepository(Repository[GraphUser]):
    """In-memory repository for ``GraphUser`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_users collection."""
        super().__init__("graph_users")


graph_user_repo = GraphUserRepository()
