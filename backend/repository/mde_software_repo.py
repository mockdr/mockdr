"""Repository for Microsoft Defender for Endpoint Software entities."""
from domain.mde_software import MdeSoftware
from repository.base import Repository


class MdeSoftwareRepository(Repository[MdeSoftware]):
    """In-memory repository for ``MdeSoftware`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the mde_software collection."""
        super().__init__("mde_software")


mde_software_repo = MdeSoftwareRepository()
