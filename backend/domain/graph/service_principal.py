"""Domain dataclass for Microsoft Graph Service Principal entity."""
from dataclasses import dataclass, field


@dataclass
class GraphServicePrincipal:
    """An Entra ID service principal (enterprise application).

    Maps 1:1 to real Graph API ``/v1.0/servicePrincipals`` response fields.
    Field names use camelCase to match the Graph API JSON format.
    """

    id: str  # noqa: A003 — GUID
    appId: str = ""  # noqa: N815
    displayName: str = ""  # noqa: N815
    publisherName: str = ""  # noqa: N815
    verifiedPublisher: dict = field(default_factory=dict)  # noqa: N815 — {displayName: str | None}
    oauth2PermissionGrants: list[dict] = field(default_factory=list)  # noqa: N815
    servicePrincipalType: str = "Application"  # noqa: N815
    accountEnabled: bool = True  # noqa: N815
    tags: list[str] = field(default_factory=list)
