"""Repository for CrowdStrike Falcon Custom IOC entities."""
from domain.cs_ioc import CsIoc
from repository.base import Repository


class CsIocRepository(Repository[CsIoc]):
    """In-memory repository for ``CsIoc`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the cs_iocs collection."""
        super().__init__("cs_iocs")



cs_ioc_repo = CsIocRepository()
