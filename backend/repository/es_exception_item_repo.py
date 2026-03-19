"""Repository for Elastic Security exception list item entities."""
from __future__ import annotations

from domain.es_exception_item import EsExceptionItem
from repository.base import Repository


class EsExceptionItemRepository(Repository[EsExceptionItem]):
    """In-memory repository for ``EsExceptionItem`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the es_exception_items collection."""
        super().__init__("es_exception_items")

    def get_by_list_id(self, list_id: str) -> list[EsExceptionItem]:
        """Return all items belonging to the given exception list."""
        return [i for i in self.list_all() if i.list_id == list_id]


es_exception_item_repo = EsExceptionItemRepository()
