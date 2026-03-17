"""Repository for Splunk KV Store collection entities."""
from domain.splunk.kv_collection import KVCollection
from repository.base import Repository


class KVCollectionRepository(Repository[KVCollection]):
    """In-memory repository for ``KVCollection`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the splunk_kv_collections collection."""
        super().__init__("splunk_kv_collections")

    def get_by_name(self, name: str, app: str = "search") -> KVCollection | None:
        """Look up a KV collection by app and name."""
        key = f"{app}/{name}"
        return self.get(key)


kv_collection_repo = KVCollectionRepository()
