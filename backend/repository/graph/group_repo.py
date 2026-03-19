"""Repository for Microsoft Graph Group entities."""
from domain.graph.group import GraphGroup
from repository.base import Repository


class GraphGroupRepository(Repository[GraphGroup]):
    """In-memory repository for ``GraphGroup`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_groups collection."""
        super().__init__("graph_groups")


graph_group_repo = GraphGroupRepository()
