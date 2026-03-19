"""Repository for CrowdStrike Falcon User entities."""
from domain.cs_user import CsUser
from repository.base import Repository


class CsUserRepository(Repository[CsUser]):
    """In-memory repository for ``CsUser`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the cs_users collection."""
        super().__init__("cs_users")


cs_user_repo = CsUserRepository()
