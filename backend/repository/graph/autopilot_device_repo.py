"""Repository for Microsoft Graph Autopilot Device Identity entities."""
from domain.graph.autopilot_device import GraphAutopilotDevice
from repository.base import Repository


class GraphAutopilotDeviceRepository(Repository[GraphAutopilotDevice]):
    """In-memory repository for ``GraphAutopilotDevice`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_autopilot_devices collection."""
        super().__init__("graph_autopilot_devices")


graph_autopilot_device_repo = GraphAutopilotDeviceRepository()
