"""Domain model for Microsoft Graph Security Alert v2."""
from dataclasses import dataclass, field


@dataclass
class GraphSecurityAlert:
    """Represents a security alert from the Microsoft Graph Security API v2."""

    id: str  # noqa: A003
    providerAlertId: str = ""  # noqa: N815
    incidentId: str = ""  # noqa: N815
    status: str = "new"  # new, inProgress, resolved, unknownFutureValue
    severity: str = "medium"  # informational, low, medium, high
    classification: str | None = None  # truePositive, falsePositive, informationalExpectedActivity
    determination: str | None = None  # malware, phishing, unwantedSoftware, etc.
    serviceSource: str = "microsoftDefenderForEndpoint"  # noqa: N815
    detectionSource: str = "customDetection"  # noqa: N815
    title: str = ""
    description: str = ""
    category: str = ""
    assignedTo: str | None = None  # noqa: N815
    createdDateTime: str = ""  # noqa: N815
    lastUpdateDateTime: str = ""  # noqa: N815
    resolvedDateTime: str | None = None  # noqa: N815
    firstActivityDateTime: str = ""  # noqa: N815
    lastActivityDateTime: str = ""  # noqa: N815
    alertWebUrl: str = ""  # noqa: N815
    tenantId: str = ""  # noqa: N815
    evidence: list[dict] = field(default_factory=list)
    comments: list[dict] = field(default_factory=list)
    mitreTechniques: list[str] = field(default_factory=list)  # noqa: N815
