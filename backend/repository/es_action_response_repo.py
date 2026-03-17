"""Repository for Elastic Security endpoint action response entities."""
from __future__ import annotations

from domain.es_action_response import EsActionResponse
from repository.base import Repository


class EsActionResponseRepository(Repository[EsActionResponse]):
    """In-memory repository for ``EsActionResponse`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the es_action_responses collection."""
        super().__init__("es_action_responses")

    def get_by_agent_id(self, agent_id: str) -> list[EsActionResponse]:
        """Return all action responses for the given endpoint."""
        return [a for a in self.list_all() if a.agent_id == agent_id]



es_action_response_repo = EsActionResponseRepository()
