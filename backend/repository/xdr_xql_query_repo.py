"""Repository for Palo Alto Cortex XDR XQL Query entities."""
from domain.xdr_xql_query import XdrXqlQuery
from repository.base import Repository


class XdrXqlQueryRepository(Repository[XdrXqlQuery]):
    """In-memory repository for ``XdrXqlQuery`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the xdr_xql_queries collection."""
        super().__init__("xdr_xql_queries")


xdr_xql_query_repo = XdrXqlQueryRepository()
