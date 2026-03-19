"""Repository for Microsoft Graph Channel Message entities."""
from domain.graph.channel_message import GraphChannelMessage
from repository.base import Repository
from repository.store import store


class GraphChannelMessageRepository(Repository[GraphChannelMessage]):
    """In-memory repository for ``GraphChannelMessage`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_channel_messages collection."""
        super().__init__("graph_channel_messages")

    def save(self, entity: GraphChannelMessage) -> None:
        """Persist a channel message, keyed by ``{team_id}:{channel_id}:{message_id}``."""
        store.save(
            self._collection,
            f"{entity._team_id}:{entity._channel_id}:{entity.id}",
            entity,
        )


graph_channel_message_repo = GraphChannelMessageRepository()
