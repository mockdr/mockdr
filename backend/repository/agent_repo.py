from domain.agent import Agent
from repository.base import Repository


class AgentRepository(Repository[Agent]):
    """Repository for Agent entities with site and group lookup helpers."""

    def __init__(self) -> None:
        """Initialise the repository bound to the agents collection."""
        super().__init__("agents")



agent_repo = AgentRepository()
