"""Repository for Elastic Security case entities."""
from __future__ import annotations

from domain.es_case import EsCase
from repository.base import Repository


class EsCaseRepository(Repository[EsCase]):
    """In-memory repository for ``EsCase`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the es_cases collection."""
        super().__init__("es_cases")



es_case_repo = EsCaseRepository()
