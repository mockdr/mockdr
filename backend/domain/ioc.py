from dataclasses import dataclass, field


@dataclass
class IOC:
    """Represents a SentinelOne threat intelligence indicator of compromise.

    Field names match the real S1 /threat-intelligence/iocs API response exactly.
    Primary key is ``uuid`` (not ``id``).  Creation timestamp is ``creationTime``
    (not ``createdAt``).
    """

    uuid: str
    type: str       # IPV4 | IPV6 | DNS | URL | SHA1 | SHA256 | MD5
    value: str
    source: str
    creationTime: str
    updatedAt: str

    # Optional metadata
    name: str | None = None
    description: str | None = None
    externalId: str | None = None
    validUntil: str | None = None
    uploadTime: str | None = None

    # Classification
    category: list = field(default_factory=list)
    severity: int | None = None
    method: str | None = None
    pattern: str | None = None
    patternType: str | None = None
    mitreTactic: list = field(default_factory=list)

    # Threat context (lists)
    campaignNames: list = field(default_factory=list)
    intrusionSets: list = field(default_factory=list)
    labels: list = field(default_factory=list)
    malwareNames: list = field(default_factory=list)
    threatActors: list = field(default_factory=list)
    threatActorTypes: list = field(default_factory=list)
    reference: list = field(default_factory=list)

    # Scope
    scope: str | None = None
    scopeId: str | None = None
    parentScopeId: str | None = None

    # Attribution
    creator: str | None = None
    batchId: str | None = None
    originalRiskScore: int | None = None

    # Metadata blob
    metadata: dict | None = None

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.uuid
