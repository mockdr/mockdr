"""Domain dataclass for Microsoft Defender for Endpoint OAuth2 client."""
from dataclasses import dataclass


@dataclass
class MdeOAuthClient:
    """An MDE OAuth2 client credentials record.

    Used to authenticate against the mock MDE API via
    ``POST /mde/oauth2/v2.0/token``.
    """

    client_id: str
    client_secret: str
    tenant_id: str
    name: str
    role: str  # "admin", "analyst", "viewer"

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.client_id
