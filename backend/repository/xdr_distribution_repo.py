"""Repository for Palo Alto Cortex XDR Distribution entities."""
from domain.xdr_distribution import XdrDistribution
from repository.base import Repository


class XdrDistributionRepository(Repository[XdrDistribution]):
    """In-memory repository for ``XdrDistribution`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the xdr_distributions collection."""
        super().__init__("xdr_distributions")


xdr_distribution_repo = XdrDistributionRepository()
