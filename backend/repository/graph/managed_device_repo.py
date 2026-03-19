"""Repository for Microsoft Graph Managed Device entities."""
from domain.graph.managed_device import GraphManagedDevice
from repository.base import Repository


class GraphManagedDeviceRepository(Repository[GraphManagedDevice]):
    """In-memory repository for ``GraphManagedDevice`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_managed_devices collection."""
        super().__init__("graph_managed_devices")


graph_managed_device_repo = GraphManagedDeviceRepository()
