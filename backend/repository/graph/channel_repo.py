"""Repository for Microsoft Graph Channel entities."""
from domain.graph.channel import GraphChannel
from repository.base import Repository
from repository.store import store


class GraphChannelRepository(Repository[GraphChannel]):
    """In-memory repository for ``GraphChannel`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_channels collection."""
        super().__init__("graph_channels")

    def save(self, entity: GraphChannel) -> None:
        """Persist a channel, keyed by ``{team_id}:{channel_id}``."""
        store.save(self._collection, f"{entity._team_id}:{entity.id}", entity)


graph_channel_repo = GraphChannelRepository()
