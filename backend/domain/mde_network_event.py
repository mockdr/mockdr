"""Domain dataclass for a Microsoft Defender for Endpoint network connection event.

Defender serves these only through Advanced Hunting, as rows of the
``DeviceNetworkEvents`` table; there is no REST resource. Field names follow
the camelCase of the other MDE domain classes, and the hunting table projects
them into the schema's column names.
"""
from dataclasses import dataclass


@dataclass
class MdeNetworkEvent:
    """One network connection a device reported, as ``DeviceNetworkEvents`` holds it."""

    eventId: str  # noqa: N815 — store key; Defender exposes ReportId instead
    reportId: int = 0  # noqa: N815
    timestamp: str = ""  # ISO 8601
    machineId: str = ""  # noqa: N815 — joins DeviceInfo.DeviceId
    computerDnsName: str = ""  # noqa: N815

    # ── Connection ────────────────────────────────────────────────────────────
    actionType: str = "ConnectionSuccess"  # noqa: N815 — ConnectionSuccess|ConnectionFailed|ConnectionAttempt
    remoteIp: str = ""  # noqa: N815
    remotePort: int = 0  # noqa: N815
    remoteUrl: str = ""  # noqa: N815 — empty when the connection named no host
    remoteIpType: str = "Public"  # noqa: N815 — Public|Private|Loopback
    localIp: str = ""  # noqa: N815
    localPort: int = 0  # noqa: N815
    protocol: str = "Tcp"

    # ── Initiating process ────────────────────────────────────────────────────
    processFileName: str = ""  # noqa: N815
    processFolderPath: str = ""  # noqa: N815 — full path, file name included, as Defender reports it
    processCommandLine: str = ""  # noqa: N815
    processId: int = 0  # noqa: N815
    processCompanyName: str = ""  # noqa: N815 — PE version info; empty off Windows
    accountDomain: str = ""  # noqa: N815
    accountName: str = ""  # noqa: N815
    accountUpn: str = ""  # noqa: N815 — empty for system accounts
    accountObjectId: str = ""  # noqa: N815

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.eventId
