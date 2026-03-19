"""Repository for Elastic Security exception list entities."""
from __future__ import annotations

from domain.es_exception_list import EsExceptionList
from repository.base import Repository


class EsExceptionListRepository(Repository[EsExceptionList]):
    """In-memory repository for ``EsExceptionList`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the es_exception_lists collection."""
        super().__init__("es_exception_lists")

    def get_by_list_id(self, list_id: str) -> EsExceptionList | None:
        """Return the first exception list matching the given list_id, or None."""
        for el in self.list_all():
            if el.list_id == list_id:
                return el
        return None



es_exception_list_repo = EsExceptionListRepository()
