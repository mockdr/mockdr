"""Domain dataclass for Microsoft Graph Group entity."""
from dataclasses import dataclass, field


@dataclass
class GraphGroup:
    """An Entra ID (Azure AD) group.

    Maps 1:1 to real Graph API ``/v1.0/groups`` response fields.
    Field names use camelCase to match the Graph API JSON format.
    """
    id: str  # noqa: A003 — GUID
    displayName: str = ""  # noqa: N815
    description: str = ""
    groupTypes: list[str] = field(default_factory=list)  # noqa: N815 — ["Unified"] for M365, [] for Security
    securityEnabled: bool = True  # noqa: N815
    mailEnabled: bool = False  # noqa: N815
    mailNickname: str = ""  # noqa: N815
    membershipRule: str | None = None  # noqa: N815 — for dynamic groups
    membershipRuleProcessingState: str | None = None  # noqa: N815 — "On" | "Paused"
    createdDateTime: str = ""  # noqa: N815
    visibility: str = "Public"  # Public | Private | HiddenMembership
