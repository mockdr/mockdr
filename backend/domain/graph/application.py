"""Domain dataclass for Microsoft Graph Application (app registration) entity."""
from dataclasses import dataclass, field


@dataclass
class GraphApplication:
    """An Entra ID application registration.

    Maps 1:1 to real Graph API ``/v1.0/applications`` response fields.
    Field names use camelCase to match the Graph API JSON format.
    """

    id: str  # noqa: A003
    appId: str = ""  # noqa: N815
    displayName: str = ""  # noqa: N815
    signInAudience: str = "AzureADMyOrg"  # noqa: N815
    createdDateTime: str = ""  # noqa: N815
    web: dict = field(default_factory=dict)
    api: dict = field(default_factory=dict)
    requiredResourceAccess: list[dict] = field(default_factory=list)  # noqa: N815
