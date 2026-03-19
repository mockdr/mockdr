"""Repository for Microsoft Graph Mail Folder entities."""
from domain.graph.mail_folder import GraphMailFolder
from repository.base import Repository
from repository.store import store


class GraphMailFolderRepository(Repository[GraphMailFolder]):
    """In-memory repository for ``GraphMailFolder`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_mail_folders collection."""
        super().__init__("graph_mail_folders")

    def save(self, entity: GraphMailFolder) -> None:
        """Persist a mail folder, keyed by ``{user_id}:{folder_id}``."""
        store.save(self._collection, f"{entity._user_id}:{entity.id}", entity)


graph_mail_folder_repo = GraphMailFolderRepository()
