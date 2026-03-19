"""Repository for Microsoft Defender for Endpoint OAuth Client entities."""
from domain.mde_oauth_client import MdeOAuthClient
from repository.base import Repository


class MdeOAuthClientRepository(Repository[MdeOAuthClient]):
    """In-memory repository for ``MdeOAuthClient`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the mde_oauth_clients collection."""
        super().__init__("mde_oauth_clients")

    def get_by_client_id(self, client_id: str) -> MdeOAuthClient | None:
        """Return the client matching the given client_id, or None."""
        return self.get(client_id)


mde_oauth_client_repo = MdeOAuthClientRepository()
