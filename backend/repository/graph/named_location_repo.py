"""Repository for Microsoft Graph Named Location entities."""
from domain.graph.named_location import GraphNamedLocation
from repository.base import Repository


class GraphNamedLocationRepository(Repository[GraphNamedLocation]):
    """In-memory repository for ``GraphNamedLocation`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_named_locations collection."""
        super().__init__("graph_named_locations")


graph_named_location_repo = GraphNamedLocationRepository()
