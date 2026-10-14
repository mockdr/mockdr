"""Repository for Microsoft Defender for Endpoint network connection events."""
from domain.mde_network_event import MdeNetworkEvent
from repository.base import Repository


class MdeNetworkEventRepository(Repository[MdeNetworkEvent]):
    """In-memory repository for ``MdeNetworkEvent`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the mde_network_events collection."""
        super().__init__("mde_network_events")


mde_network_event_repo = MdeNetworkEventRepository()
