"""Domain model for Microsoft Graph Identity Protection Risky User."""
from dataclasses import dataclass


@dataclass
class GraphRiskyUser:
    """Represents an Entra ID user flagged as risky by Identity Protection."""

    id: str  # noqa: A003 — same as user ID
    userPrincipalName: str = ""  # noqa: N815
    userDisplayName: str = ""  # noqa: N815
    riskLevel: str = "low"  # noqa: N815 — none, low, medium, high, hidden
    riskState: str = "atRisk"  # noqa: N815 — none, confirmedSafe, remediated, dismissed, atRisk, confirmedCompromised
    riskDetail: str = "none"  # noqa: N815
    riskLastUpdatedDateTime: str = ""  # noqa: N815
    isProcessing: bool = False  # noqa: N815
    isDeleted: bool = False  # noqa: N815
