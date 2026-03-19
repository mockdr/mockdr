"""Domain dataclass for Microsoft Graph User Registration Detail entity."""
from dataclasses import dataclass, field


@dataclass
class GraphUserRegistrationDetail:
    """An Entra ID user registration detail for authentication methods.

    Maps 1:1 to real Graph API
    ``/v1.0/reports/authenticationMethods/userRegistrationDetails`` response fields.
    """

    id: str  # noqa: A003 — user ID
    userPrincipalName: str = ""  # noqa: N815
    userDisplayName: str = ""  # noqa: N815
    isMfaRegistered: bool = False  # noqa: N815
    isMfaCapable: bool = False  # noqa: N815
    methodsRegistered: list[str] = field(default_factory=list)  # noqa: N815
    defaultMfaMethod: str = ""  # noqa: N815
    isPasswordlessCapable: bool = False  # noqa: N815
    isSsprRegistered: bool = False  # noqa: N815
    isSsprEnabled: bool = False  # noqa: N815
    isSsprCapable: bool = False  # noqa: N815
