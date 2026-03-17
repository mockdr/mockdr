from domain.dv_query import DVQuery
from repository.base import Repository


class DVQueryRepository(Repository[DVQuery]):
    """Repository for Deep Visibility query entities."""

    def __init__(self) -> None:
        """Initialise the repository bound to the dv_queries collection."""
        super().__init__("dv_queries")


dv_query_repo = DVQueryRepository()
