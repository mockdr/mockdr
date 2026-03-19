"""Repository for Microsoft Graph Sign-In Log entities."""
from domain.graph.sign_in_log import GraphSignInLog
from repository.base import Repository


class GraphSignInLogRepository(Repository[GraphSignInLog]):
    """In-memory repository for ``GraphSignInLog`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_sign_in_logs collection."""
        super().__init__("graph_sign_in_logs")


graph_sign_in_log_repo = GraphSignInLogRepository()
