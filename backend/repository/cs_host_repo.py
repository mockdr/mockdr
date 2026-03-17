"""Repository for CrowdStrike Falcon Host entities."""
from domain.cs_host import CsHost
from repository.base import Repository


class CsHostRepository(Repository[CsHost]):
    """In-memory repository for ``CsHost`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the cs_hosts collection."""
        super().__init__("cs_hosts")



cs_host_repo = CsHostRepository()
