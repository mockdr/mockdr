"""Domain model for Microsoft Graph Threat Assessment Request."""
from dataclasses import dataclass, field


@dataclass
class GraphThreatAssessment:
    """Represents a threat assessment request from Defender for Office 365."""

    id: str  # noqa: A003
    contentType: str = ""  # noqa: N815 — mail, file, url
    expectedAssessment: str = "block"  # noqa: N815 — block, unblock
    status: str = "completed"  # completed, pending
    category: str = "phishing"  # spam, phishing, malware
    result: dict = field(default_factory=dict)  # {resultType: "checkPolicy", message: "..."}
    createdDateTime: str = ""  # noqa: N815
    requestSource: str = "administrator"  # noqa: N815
