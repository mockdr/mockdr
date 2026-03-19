"""Repository for Palo Alto Cortex XDR hash exception entities."""
from domain.xdr_hash_exception import XdrHashException
from repository.base import Repository


class XdrHashExceptionRepository(Repository[XdrHashException]):
    """In-memory repository for ``XdrHashException`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the xdr_hash_exceptions collection."""
        super().__init__("xdr_hash_exceptions")


xdr_hash_exception_repo = XdrHashExceptionRepository()
