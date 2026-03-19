"""Domain dataclass for Microsoft Graph Sign-In Log entity."""
from dataclasses import dataclass, field


@dataclass
class GraphSignInLog:
    """An Entra ID sign-in log entry.

    Maps 1:1 to real Graph API ``/v1.0/auditLogs/signIns`` response fields.
    Field names use camelCase to match the Graph API JSON format.
    """
    id: str  # noqa: A003
    createdDateTime: str = ""  # noqa: N815
    userDisplayName: str = ""  # noqa: N815
    userPrincipalName: str = ""  # noqa: N815
    userId: str = ""  # noqa: N815
    appId: str = ""  # noqa: N815
    appDisplayName: str = ""  # noqa: N815
    ipAddress: str = ""  # noqa: N815
    clientAppUsed: str = ""  # noqa: N815 — Browser, Mobile Apps and Desktop clients, Exchange ActiveSync
    location: dict = field(default_factory=dict)  # city, state, etc.
    status: dict = field(default_factory=dict)  # {errorCode: int, failureReason: str}
    conditionalAccessStatus: str = "notApplied"  # noqa: N815 — success, failure, notApplied
    isInteractive: bool = True  # noqa: N815
    riskLevelAggregated: str = "none"  # noqa: N815 — none, low, medium, high, hidden
    riskLevelDuringSignIn: str = "none"  # noqa: N815
    riskState: str = "none"  # noqa: N815
    resourceDisplayName: str = ""  # noqa: N815
    resourceId: str = ""  # noqa: N815
    appliedConditionalAccessPolicies: list[dict] = field(default_factory=list)  # noqa: N815
