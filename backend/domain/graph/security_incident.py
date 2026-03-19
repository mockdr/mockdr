"""Domain model for Microsoft Graph Security Incident."""
from dataclasses import dataclass, field


@dataclass
class GraphSecurityIncident:
    """Represents a security incident from the Microsoft Graph Security API."""

    id: str  # noqa: A003
    displayName: str = ""  # noqa: N815
    severity: str = "medium"
    status: str = "active"  # active, resolved, redirected
    classification: str | None = None
    determination: str | None = None
    assignedTo: str | None = None  # noqa: N815
    createdDateTime: str = ""  # noqa: N815
    lastUpdateDateTime: str = ""  # noqa: N815
    alert_ids: list[str] = field(default_factory=list)  # internal -- for $expand=alerts
    comments: list[dict] = field(default_factory=list)
    tenantId: str = ""  # noqa: N815
    incidentWebUrl: str = ""  # noqa: N815
