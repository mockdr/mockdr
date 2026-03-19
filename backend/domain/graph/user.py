"""Domain dataclass for Microsoft Graph User entity."""
from dataclasses import dataclass, field


@dataclass
class GraphUser:
    """An Entra ID (Azure AD) user.

    Maps 1:1 to real Graph API ``/v1.0/users`` response fields.
    Field names use camelCase to match the Graph API JSON format.
    """
    id: str  # noqa: A003 — GUID
    userPrincipalName: str = ""  # noqa: N815
    displayName: str = ""  # noqa: N815
    mail: str | None = None
    givenName: str | None = None  # noqa: N815
    surname: str | None = None
    jobTitle: str | None = None  # noqa: N815
    department: str | None = None
    officeLocation: str | None = None  # noqa: N815
    mobilePhone: str | None = None  # noqa: N815
    businessPhones: list[str] = field(default_factory=list)  # noqa: N815
    accountEnabled: bool = True  # noqa: N815
    companyName: str | None = None  # noqa: N815
    city: str | None = None
    country: str | None = None
    assignedLicenses: list[dict] = field(default_factory=list)  # noqa: N815
    assignedPlans: list[dict] = field(default_factory=list)  # noqa: N815
    createdDateTime: str = ""  # noqa: N815
    signInActivity: dict = field(default_factory=dict)  # noqa: N815 — {lastSignInDateTime, lastNonInteractiveSignInDateTime}
