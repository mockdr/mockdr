"""Repository for Palo Alto Cortex XDR API Key entities."""
from domain.xdr_api_key import XdrApiKey
from repository.base import Repository


class XdrApiKeyRepository(Repository[XdrApiKey]):
    """In-memory repository for ``XdrApiKey`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the xdr_api_keys collection."""
        super().__init__("xdr_api_keys")

    def get_by_key_id(self, key_id: str) -> XdrApiKey | None:
        """Look up an API key by its ``key_id`` field using a dict-based index.

        Args:
            key_id: The API key ID to search for.

        Returns:
            The matching ``XdrApiKey`` or ``None``.
        """
        all_keys = self.list_all()
        index = {k.key_id: k for k in all_keys}
        return index.get(key_id)



xdr_api_key_repo = XdrApiKeyRepository()
