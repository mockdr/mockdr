"""Repository for Microsoft Graph Device Category entities."""
from domain.graph.device_category import GraphDeviceCategory
from repository.base import Repository


class GraphDeviceCategoryRepository(Repository[GraphDeviceCategory]):
    """In-memory repository for ``GraphDeviceCategory`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_device_categories collection."""
        super().__init__("graph_device_categories")


graph_device_category_repo = GraphDeviceCategoryRepository()
