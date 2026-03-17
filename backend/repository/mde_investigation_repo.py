"""Repository for Microsoft Defender for Endpoint Investigation entities."""
from domain.mde_investigation import MdeInvestigation
from repository.base import Repository


class MdeInvestigationRepository(Repository[MdeInvestigation]):
    """In-memory repository for ``MdeInvestigation`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the mde_investigations collection."""
        super().__init__("mde_investigations")


mde_investigation_repo = MdeInvestigationRepository()
