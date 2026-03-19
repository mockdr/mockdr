"""Repository for Microsoft Graph Mail Message entities."""
from domain.graph.mail_message import GraphMailMessage
from repository.base import Repository
from repository.store import store


class GraphMailMessageRepository(Repository[GraphMailMessage]):
    """In-memory repository for ``GraphMailMessage`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_mail_messages collection."""
        super().__init__("graph_mail_messages")

    def save(self, entity: GraphMailMessage) -> None:
        """Persist a mail message, keyed by ``{user_id}:{message_id}``."""
        store.save(self._collection, f"{entity._user_id}:{entity.id}", entity)


graph_mail_message_repo = GraphMailMessageRepository()
