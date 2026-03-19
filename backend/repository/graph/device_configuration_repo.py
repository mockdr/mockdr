"""Repository for Microsoft Graph Device Configuration entities."""
from domain.graph.device_configuration import GraphDeviceConfiguration
from repository.base import Repository


class GraphDeviceConfigurationRepository(Repository[GraphDeviceConfiguration]):
    """In-memory repository for ``GraphDeviceConfiguration`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_device_configurations collection."""
        super().__init__("graph_device_configurations")


graph_device_configuration_repo = GraphDeviceConfigurationRepository()
