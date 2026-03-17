from domain.site import Site
from repository.base import Repository


class SiteRepository(Repository[Site]):
    """Repository for Site entities."""

    def __init__(self) -> None:
        """Initialise the repository bound to the sites collection."""
        super().__init__("sites")


site_repo = SiteRepository()
