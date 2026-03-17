"""Repository for CrowdStrike Falcon Quarantined File entities."""
from domain.cs_quarantined_file import CsQuarantinedFile
from repository.base import Repository


class CsQuarantineRepository(Repository[CsQuarantinedFile]):
    """In-memory repository for ``CsQuarantinedFile`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the cs_quarantined_files collection."""
        super().__init__("cs_quarantined_files")


cs_quarantine_repo = CsQuarantineRepository()
