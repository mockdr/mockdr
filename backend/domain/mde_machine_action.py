"""Domain dataclass for Microsoft Defender for Endpoint Machine Action entity."""
from dataclasses import dataclass, field


@dataclass
class MdeMachineAction:
    """An async machine action tracked via ``/api/machineactions``.

    Actions are created by POST endpoints (isolate, scan, etc.) and start
    with ``status="Pending"``.  The GET handler auto-promotes to
    ``"Succeeded"`` after a short delay.
    """

    actionId: str  # noqa: N815 — GUID
    type: str = ""  # Isolate|Unisolate|RunAntiVirusScan|...
    status: str = "Pending"  # Pending|InProgress|Succeeded|Failed|TimeOut|Cancelled
    machineId: str = ""  # noqa: N815
    creationDateTimeUtc: str = ""  # noqa: N815
    lastUpdateDateTimeUtc: str = ""  # noqa: N815
    requestor: str = ""
    requestorComment: str = ""  # noqa: N815
    cancellationRequestor: str = ""  # noqa: N815
    scope: str = "Full"  # Full|Selective
    commands: list[dict] = field(default_factory=list)

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.actionId
