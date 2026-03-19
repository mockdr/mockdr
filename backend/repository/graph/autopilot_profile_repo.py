"""Repository for Microsoft Graph Autopilot Deployment Profile entities."""
from domain.graph.autopilot_profile import GraphAutopilotProfile
from repository.base import Repository


class GraphAutopilotProfileRepository(Repository[GraphAutopilotProfile]):
    """In-memory repository for ``GraphAutopilotProfile`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_autopilot_profiles collection."""
        super().__init__("graph_autopilot_profiles")


graph_autopilot_profile_repo = GraphAutopilotProfileRepository()
