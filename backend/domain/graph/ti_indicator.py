"""Domain model for Microsoft Graph Threat Intelligence Indicator."""
from dataclasses import dataclass


@dataclass
class GraphTiIndicator:
    """A ``microsoft.graph.tiIndicator``.

    The property set is the one Graph declares, taken from
    ``data/vendor-specs/graph_beta_csdl_types.json``. It comes from the beta
    metadata because Microsoft retired ``tiIndicator`` from v1.0 and removed
    the type with it, while the route stays reachable and SOAR playbooks
    written against it keep calling.

    Until that reference was vendored the model carried ``indicatorValue``
    and ``indicatorType``, which Graph has never had: an observable was
    stored under a name no client reads, and a client that sent the
    documented ``domainName`` got a 201 and lost it. The observable now
    lives in the typed property that names it — ``domainName``, ``url``,
    ``fileHashValue`` with its ``fileHashType``, ``networkDestinationIPv4``.
    """

    id: str  # noqa: A003
    action: str | None = None
    activityGroupNames: list[str] | None = None  # noqa: N815
    additionalInformation: str | None = None  # noqa: N815
    azureTenantId: str | None = None  # noqa: N815
    confidence: int | None = None
    description: str | None = None
    diamondModel: str | None = None  # noqa: N815
    domainName: str | None = None  # noqa: N815
    emailEncoding: str | None = None  # noqa: N815
    emailLanguage: str | None = None  # noqa: N815
    emailRecipient: str | None = None  # noqa: N815
    emailSenderAddress: str | None = None  # noqa: N815
    emailSenderName: str | None = None  # noqa: N815
    emailSourceDomain: str | None = None  # noqa: N815
    emailSourceIpAddress: str | None = None  # noqa: N815
    emailSubject: str | None = None  # noqa: N815
    emailXMailer: str | None = None  # noqa: N815
    expirationDateTime: str | None = None  # noqa: N815
    externalId: str | None = None  # noqa: N815
    fileCompileDateTime: str | None = None  # noqa: N815
    fileCreatedDateTime: str | None = None  # noqa: N815
    fileHashType: str | None = None  # noqa: N815
    fileHashValue: str | None = None  # noqa: N815
    fileMutexName: str | None = None  # noqa: N815
    fileName: str | None = None  # noqa: N815
    filePacker: str | None = None  # noqa: N815
    filePath: str | None = None  # noqa: N815
    fileSize: int | None = None  # noqa: N815
    fileType: str | None = None  # noqa: N815
    ingestedDateTime: str | None = None  # noqa: N815
    isActive: bool | None = None  # noqa: N815
    killChain: list[str] | None = None  # noqa: N815
    knownFalsePositives: str | None = None  # noqa: N815
    lastReportedDateTime: str | None = None  # noqa: N815
    malwareFamilyNames: list[str] | None = None  # noqa: N815
    networkCidrBlock: str | None = None  # noqa: N815
    networkDestinationAsn: int | None = None  # noqa: N815
    networkDestinationCidrBlock: str | None = None  # noqa: N815
    networkDestinationIPv4: str | None = None  # noqa: N815
    networkDestinationIPv6: str | None = None  # noqa: N815
    networkDestinationPort: int | None = None  # noqa: N815
    networkIPv4: str | None = None  # noqa: N815
    networkIPv6: str | None = None  # noqa: N815
    networkPort: int | None = None  # noqa: N815
    networkProtocol: int | None = None  # noqa: N815
    networkSourceAsn: int | None = None  # noqa: N815
    networkSourceCidrBlock: str | None = None  # noqa: N815
    networkSourceIPv4: str | None = None  # noqa: N815
    networkSourceIPv6: str | None = None  # noqa: N815
    networkSourcePort: int | None = None  # noqa: N815
    passiveOnly: bool | None = None  # noqa: N815
    severity: int | None = None
    tags: list[str] | None = None
    targetProduct: str | None = None  # noqa: N815
    threatType: str | None = None  # noqa: N815
    tlpLevel: str | None = None  # noqa: N815
    url: str | None = None
    userAgent: str | None = None  # noqa: N815
