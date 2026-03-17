from domain.threat import Threat
from repository.base import Repository


class ThreatRepository(Repository[Threat]):
    """Repository for Threat entities with agent-scoped lookup."""

    def __init__(self) -> None:
        """Initialise the repository bound to the threats collection."""
        super().__init__("threats")



threat_repo = ThreatRepository()
