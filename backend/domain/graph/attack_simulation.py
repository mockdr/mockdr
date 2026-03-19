"""Domain model for Microsoft Graph Attack Simulation."""
from dataclasses import dataclass, field


@dataclass
class GraphAttackSimulation:
    """Represents an attack simulation from Defender for Office 365."""

    id: str  # noqa: A003
    displayName: str = ""  # noqa: N815
    status: str = "succeeded"  # succeeded, completed, draft, running
    launchDateTime: str = ""  # noqa: N815
    completionDateTime: str = ""  # noqa: N815
    attackTechnique: str = ""  # noqa: N815 — credentialHarvesting, linkInAttachment, driveByUrl
    attackType: str = ""  # noqa: N815 — social, cloud
    report: dict = field(default_factory=dict)  # overview/simulationUsers
    createdDateTime: str = ""  # noqa: N815
