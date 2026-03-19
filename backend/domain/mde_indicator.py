"""Domain dataclass for Microsoft Defender for Endpoint Indicator (IoC) entity."""
from dataclasses import dataclass, field


@dataclass
class MdeIndicator:
    """An MDE threat indicator from the ``/api/indicators`` endpoint.

    Field names use camelCase to match the real MDE API exactly.
    """

    indicatorId: str  # noqa: N815 — GUID
    indicatorValue: str = ""  # noqa: N815
    indicatorType: str = ""  # noqa: N815 — FileSha1|FileSha256|IpAddress|DomainName|Url
    action: str = "Alert"  # Alert|AlertAndBlock|Allowed|Audit|Block|BlockAndRemediate|Warn
    severity: str = "Medium"
    title: str = ""
    description: str = ""
    recommendedActions: str = ""  # noqa: N815
    rbacGroupNames: list[str] = field(default_factory=list)  # noqa: N815
    generateAlert: bool = True  # noqa: N815
    createdBy: str = ""  # noqa: N815
    createdByDisplayName: str = ""  # noqa: N815
    createdBySource: str = "User"  # noqa: N815 — User|WindowsDefenderAtp
    creationTimeDateTimeUtc: str = ""  # noqa: N815
    expirationTime: str = ""  # noqa: N815
    lastUpdatedBy: str = ""  # noqa: N815
    lastUpdateTime: str = ""  # noqa: N815

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.indicatorId
