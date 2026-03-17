"""Repository for Palo Alto Cortex XDR Action entities."""
from domain.xdr_action import XdrAction
from repository.base import Repository


class XdrActionRepository(Repository[XdrAction]):
    """In-memory repository for ``XdrAction`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the xdr_actions collection."""
        super().__init__("xdr_actions")



xdr_action_repo = XdrActionRepository()
