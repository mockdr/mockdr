"""Domain dataclass for Microsoft Defender for Endpoint Machine (device) entity.

Field names use camelCase to match the real MDE API response format exactly,
so ``dataclasses.asdict()`` produces correct output without transformation.
"""
from dataclasses import dataclass, field


@dataclass
class MdeMachine:
    """A Microsoft Defender for Endpoint managed machine/device.

    Maps 1:1 to real MDE API ``/api/machines`` response fields.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    machineId: str  # noqa: N815 — GUID
    computerDnsName: str  # noqa: N815

    # ── OS ────────────────────────────────────────────────────────────────────
    osPlatform: str = ""  # noqa: N815 — "Windows10", "WindowsServer2022", "macOS", "Linux"
    osVersion: str = ""  # noqa: N815
    osProcessor: str = "x64"  # noqa: N815 — "x64", "ARM64"
    osBuild: int = 0  # noqa: N815

    # ── Health / Risk ─────────────────────────────────────────────────────────
    healthStatus: str = "Active"  # noqa: N815 — Active|Inactive|ImpairedCommunication|NoSensorData
    riskScore: str = "None"  # noqa: N815 — None|Low|Medium|High
    exposureLevel: str = "None"  # noqa: N815 — None|Low|Medium|High
    onboardingStatus: str = "Onboarded"  # noqa: N815
    sensorHealthState: str = "Active"  # noqa: N815

    # ── Timestamps ────────────────────────────────────────────────────────────
    lastSeen: str = ""  # noqa: N815 — ISO 8601
    firstSeen: str = ""  # noqa: N815

    # ── Tags / Groups ─────────────────────────────────────────────────────────
    machineTags: list[str] = field(default_factory=list)  # noqa: N815
    rbacGroupId: int = 0  # noqa: N815
    rbacGroupName: str = ""  # noqa: N815

    # ── Azure AD ──────────────────────────────────────────────────────────────
    aadDeviceId: str = ""  # noqa: N815
    isAadJoined: bool = True  # noqa: N815

    # ── Network ───────────────────────────────────────────────────────────────
    lastIpAddress: str = ""  # noqa: N815
    lastExternalIpAddress: str = ""  # noqa: N815
    ipAddresses: list[dict] = field(default_factory=list)  # noqa: N815

    # ── Agent ─────────────────────────────────────────────────────────────────
    agentVersion: str = ""  # noqa: N815

    # ── Users ─────────────────────────────────────────────────────────────────
    loggedOnUsers: list[dict] = field(default_factory=list)  # noqa: N815

    # ── Group / Managed By ────────────────────────────────────────────────────
    groupName: str = ""  # noqa: N815
    managedBy: str = "MDE"  # noqa: N815
    managedByStatus: str = "Active"  # noqa: N815

    # ── VM metadata ───────────────────────────────────────────────────────────
    vmMetadata: dict | None = None  # noqa: N815

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.machineId
