"""Repository for Palo Alto Cortex XDR Script entities."""
from domain.xdr_script import XdrScript
from repository.base import Repository


class XdrScriptRepository(Repository[XdrScript]):
    """In-memory repository for ``XdrScript`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the xdr_scripts collection."""
        super().__init__("xdr_scripts")


xdr_script_repo = XdrScriptRepository()
