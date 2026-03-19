"""Domain dataclass for Microsoft Defender for Endpoint Alert entity."""
from dataclasses import dataclass, field


@dataclass
class MdeAlert:
    """An MDE alert from the ``/api/alerts`` endpoint.

    Field names use camelCase to match the real MDE API exactly.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    alertId: str  # noqa: N815 — GUID

    # ── Core ──────────────────────────────────────────────────────────────────
    title: str = ""
    description: str = ""
    severity: str = "Medium"  # Informational|Low|Medium|High
    status: str = "New"  # New|InProgress|Resolved
    classification: str = ""  # TruePositive|FalsePositive|BenignPositive
    determination: str = ""  # Malware|NotMalware|Phishing|Other

    # ── Assignment ────────────────────────────────────────────────────────────
    assignedTo: str = ""  # noqa: N815

    # ── Links ─────────────────────────────────────────────────────────────────
    machineId: str = ""  # noqa: N815
    incidentId: int = 0  # noqa: N815
    investigationId: int = 0  # noqa: N815
    investigationState: str = ""  # noqa: N815

    # ── Detection ─────────────────────────────────────────────────────────────
    category: str = ""  # Malware|SuspiciousActivity|Ransomware|CredentialAccess|...
    detectionSource: str = "WindowsDefenderAtp"  # noqa: N815
    threatName: str = ""  # noqa: N815
    threatFamilyName: str = ""  # noqa: N815

    # ── Timestamps ────────────────────────────────────────────────────────────
    alertCreationTime: str = ""  # noqa: N815
    lastUpdateTime: str = ""  # noqa: N815
    resolvedTime: str = ""  # noqa: N815
    firstEventTime: str = ""  # noqa: N815
    lastEventTime: str = ""  # noqa: N815

    # ── Evidence & Comments ───────────────────────────────────────────────────
    comments: list[dict] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.alertId
