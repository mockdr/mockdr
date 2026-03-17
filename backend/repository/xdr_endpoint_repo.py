"""Repository for Palo Alto Cortex XDR Endpoint entities."""
from domain.xdr_endpoint import XdrEndpoint
from repository.base import Repository


class XdrEndpointRepository(Repository[XdrEndpoint]):
    """In-memory repository for ``XdrEndpoint`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the xdr_endpoints collection."""
        super().__init__("xdr_endpoints")


xdr_endpoint_repo = XdrEndpointRepository()
