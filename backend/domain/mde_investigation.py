"""Domain dataclass for Microsoft Defender for Endpoint Investigation entity."""
from dataclasses import dataclass


@dataclass
class MdeInvestigation:
    """An automated investigation from ``/api/investigations``.

    Investigations are triggered by alerts and track remediation progress.
    """

    investigationId: str  # noqa: N815 — GUID
    startTime: str = ""  # noqa: N815
    endTime: str = ""  # noqa: N815
    state: str = "Running"  # Running|Queued|TerminatedByUser|...
    cancelledBy: str = ""  # noqa: N815
    statusDetails: str = ""  # noqa: N815
    machineId: str = ""  # noqa: N815
    computerDnsName: str = ""  # noqa: N815
    triggeringAlertId: str = ""  # noqa: N815

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.investigationId
