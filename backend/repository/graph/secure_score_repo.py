"""Repository for Microsoft Graph Secure Score entities."""
from domain.graph.secure_score import GraphSecureScore
from repository.base import Repository


class GraphSecureScoreRepository(Repository[GraphSecureScore]):
    """In-memory repository for ``GraphSecureScore`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_secure_scores collection."""
        super().__init__("graph_secure_scores")


graph_secure_score_repo = GraphSecureScoreRepository()
