"""Repository for Microsoft Graph Team entities."""
from domain.graph.team import GraphTeam
from repository.base import Repository


class GraphTeamRepository(Repository[GraphTeam]):
    """In-memory repository for ``GraphTeam`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_teams collection."""
        super().__init__("graph_teams")


graph_team_repo = GraphTeamRepository()
