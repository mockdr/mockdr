"""Domain dataclass for CrowdStrike Falcon OAuth2 client credentials."""
from dataclasses import dataclass


@dataclass
class CsOAuthClient:
    """A CrowdStrike Falcon OAuth2 API client.

    ``client_secret`` is internal-only and must never appear in API responses.
    The ``id`` property aliases ``client_id`` so the generic Repository[T]
    pattern works unchanged.
    """

    client_id: str
    client_secret: str
    name: str = ""
    role: str = "admin"
    member_cid: str = ""

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.client_id
