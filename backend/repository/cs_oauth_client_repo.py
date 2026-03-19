"""Repository for CrowdStrike Falcon OAuth2 client entities."""
from domain.cs_oauth_client import CsOAuthClient
from repository.base import Repository


class CsOAuthClientRepository(Repository[CsOAuthClient]):
    """In-memory repository for ``CsOAuthClient`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the cs_oauth_clients collection."""
        super().__init__("cs_oauth_clients")

    def get_by_secret(self, client_id: str, client_secret: str) -> CsOAuthClient | None:
        """Return the client matching both ID and secret, or None.

        Args:
            client_id: The OAuth2 client identifier.
            client_secret: The OAuth2 client secret.

        Returns:
            The matching client, or None if credentials are invalid.
        """
        client = self.get(client_id)
        if client is not None and client.client_secret == client_secret:
            return client
        return None


cs_oauth_client_repo = CsOAuthClientRepository()
