"""Domain dataclass for a Microsoft Graph OAuth2 client registration."""
from dataclasses import dataclass, field


@dataclass
class GraphOAuthClient:
    """A pre-registered OAuth2 client for the Graph API mock.

    Each client is associated with a plan level and a set of licenses
    that determine which Graph API features are accessible.
    """

    client_id: str
    client_secret: str
    tenant_id: str = ""
    name: str = ""
    plan: str = "plan1"  # plan1 | plan2 | defender_for_business | none
    licenses: list[str] = field(default_factory=list)  # e.g. ["E5", "Intune"]
    role: str = "reader"  # reader | contributor | owner

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.client_id
