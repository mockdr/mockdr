"""Repository for Microsoft Graph OAuth2 client registrations."""
from domain.graph.oauth_client import GraphOAuthClient
from repository.base import Repository


class GraphOAuthClientRepository(Repository[GraphOAuthClient]):
    """In-memory repository for ``GraphOAuthClient`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_oauth_clients collection."""
        super().__init__("graph_oauth_clients")


graph_oauth_client_repo = GraphOAuthClientRepository()
