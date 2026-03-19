"""Domain model for Microsoft Graph Identity Protection Risk Detection."""
from dataclasses import dataclass, field


@dataclass
class GraphRiskDetection:
    """Represents a risk detection event from Entra ID Identity Protection."""

    id: str  # noqa: A003
    userId: str = ""  # noqa: N815
    userPrincipalName: str = ""  # noqa: N815
    userDisplayName: str = ""  # noqa: N815
    riskEventType: str = ""  # noqa: N815 — anonymizedIPAddress, unfamiliarFeatures, malwareInfectedIPAddress, leakedCredentials, passwordSpray, impossibleTravel
    riskLevel: str = "low"  # noqa: N815
    riskState: str = "atRisk"  # noqa: N815
    riskDetail: str = "none"  # noqa: N815
    ipAddress: str = ""  # noqa: N815
    location: dict = field(default_factory=dict)
    detectedDateTime: str = ""  # noqa: N815
    lastUpdatedDateTime: str = ""  # noqa: N815
    activityDateTime: str = ""  # noqa: N815
    detectionTimingType: str = "realtime"  # noqa: N815 — realtime, offline
    activity: str = "signin"  # signin, user
    source: str = "IdentityProtection"
    tokenIssuerType: str = "AzureAD"  # noqa: N815
