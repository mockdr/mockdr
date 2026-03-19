"""Repository for Microsoft Graph Update Ring entities."""
from domain.graph.update_ring import GraphUpdateRing
from repository.base import Repository


class GraphUpdateRingRepository(Repository[GraphUpdateRing]):
    """In-memory repository for ``GraphUpdateRing`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_update_rings collection."""
        super().__init__("graph_update_rings")


graph_update_ring_repo = GraphUpdateRingRepository()
