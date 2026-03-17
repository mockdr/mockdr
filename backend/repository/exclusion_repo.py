from domain.exclusion import Exclusion
from repository.base import Repository


class ExclusionRepository(Repository[Exclusion]):
    """Repository for Exclusion entities."""

    def __init__(self) -> None:
        """Initialise the repository bound to the exclusions collection."""
        super().__init__("exclusions")


exclusion_repo = ExclusionRepository()
