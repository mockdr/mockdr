"""Repository for Microsoft Graph Drive Item entities."""
from domain.graph.drive_item import GraphDriveItem
from repository.base import Repository
from repository.store import store


class GraphDriveItemRepository(Repository[GraphDriveItem]):
    """In-memory repository for ``GraphDriveItem`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_drive_items collection."""
        super().__init__("graph_drive_items")

    def save(self, entity: GraphDriveItem) -> None:
        """Persist a drive item, keyed by ``{drive_id}:{item_id}``."""
        store.save(self._collection, f"{entity._drive_id}:{entity.id}", entity)


graph_drive_item_repo = GraphDriveItemRepository()
