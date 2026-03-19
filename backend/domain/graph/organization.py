"""Domain dataclass for Microsoft Graph Organization entity."""
from dataclasses import dataclass, field


@dataclass
class GraphOrganization:
    """An Azure AD / Entra ID organization (tenant).

    Maps 1:1 to real Graph API ``/v1.0/organization`` response fields.
    """

    id: str  # noqa: A003 — tenant GUID
    displayName: str = ""  # noqa: N815
    verifiedDomains: list[dict] = field(default_factory=list)  # noqa: N815
    assignedPlans: list[dict] = field(default_factory=list)  # noqa: N815
    tenantType: str = "AAD"  # noqa: N815
    createdDateTime: str = ""  # noqa: N815
    city: str = ""
    country: str = ""
    postalCode: str = ""  # noqa: N815
    state: str = ""
    street: str = ""
