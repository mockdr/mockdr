"""Repository for CrowdStrike Falcon Case entities."""
from domain.cs_case import CsCase
from repository.base import Repository


class CsCaseRepository(Repository[CsCase]):
    """In-memory repository for ``CsCase`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the cs_cases collection."""
        super().__init__("cs_cases")


cs_case_repo = CsCaseRepository()
