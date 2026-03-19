"""Domain model for Microsoft Graph Secure Score."""
from dataclasses import dataclass, field


@dataclass
class GraphSecureScore:
    """Represents a secure score snapshot from the Microsoft Graph Security API."""

    id: str  # noqa: A003
    azureTenantId: str = ""  # noqa: N815
    currentScore: float = 0.0  # noqa: N815
    maxScore: float = 100.0  # noqa: N815
    createdDateTime: str = ""  # noqa: N815
    controlScores: list[dict] = field(default_factory=list)  # noqa: N815
