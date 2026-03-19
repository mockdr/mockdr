"""Repository for CrowdStrike Falcon Host Group entities."""
from domain.cs_host_group import CsHostGroup
from repository.base import Repository


class CsHostGroupRepository(Repository[CsHostGroup]):
    """In-memory repository for ``CsHostGroup`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the cs_host_groups collection."""
        super().__init__("cs_host_groups")


cs_host_group_repo = CsHostGroupRepository()
