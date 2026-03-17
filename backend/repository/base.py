"""Generic repository base — one instance per domain collection."""
from typing import Generic, TypeVar

from repository.store import store

T = TypeVar("T")


class Repository(Generic[T]):
    """Generic in-memory repository backed by the global store."""

    def __init__(self, collection: str) -> None:
        """Initialise the repository for the given named collection.

        Args:
            collection: Name of the store collection to use.
        """
        self._collection = collection

    def get(self, id: str) -> T | None:
        """Return the entity with the given ID, or None if not found."""
        return store.get(self._collection, id)

    def list_all(self) -> list[T]:
        """Return all entities in the collection."""
        return store.get_all(self._collection)

    def save(self, entity: T) -> None:
        """Persist an entity, keyed by its ``id`` attribute."""
        store.save(self._collection, entity.id, entity)  # type: ignore[attr-defined]

    def save_raw(self, id: str, record: dict) -> None:
        """Persist a raw dict record under the given ID."""
        store.save(self._collection, id, record)

    def delete(self, id: str) -> bool:
        """Delete the entity with the given ID.

        Returns:
            True if the entity existed and was deleted, False otherwise.
        """
        return store.delete(self._collection, id)

    def exists(self, id: str) -> bool:
        """Return True if an entity with the given ID exists in the collection."""
        return store.exists(self._collection, id)

    def count(self) -> int:
        """Return the total number of entities in the collection."""
        return store.count(self._collection)
