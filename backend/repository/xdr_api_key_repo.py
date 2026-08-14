"""Repository for Palo Alto Cortex XDR API Key entities."""
from domain.xdr_api_key import XdrApiKey
from repository.base import Repository


class XdrApiKeyRepository(Repository[XdrApiKey]):
    """In-memory repository for ``XdrApiKey`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the xdr_api_keys collection."""
        super().__init__("xdr_api_keys")

    def get_by_key_id(self, key_id: str) -> XdrApiKey | None:
        """Look up an API key by its ``key_id`` field.

        ``key_id`` is the collection's primary key, so this is a single dict
        lookup — the previous implementation scanned every record to build a
        throwaway index on each call.

        Args:
            key_id: The API key ID to search for.

        Returns:
            The matching ``XdrApiKey`` or ``None``.
        """
        return self.get(key_id)



xdr_api_key_repo = XdrApiKeyRepository()
