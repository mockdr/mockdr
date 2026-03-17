"""Repository for Palo Alto Cortex XDR IOC entities."""
from domain.xdr_ioc import XdrIoc
from repository.base import Repository


class XdrIocRepository(Repository[XdrIoc]):
    """In-memory repository for ``XdrIoc`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the xdr_iocs collection."""
        super().__init__("xdr_iocs")


xdr_ioc_repo = XdrIocRepository()
