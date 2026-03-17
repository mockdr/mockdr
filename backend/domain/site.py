from dataclasses import dataclass, field


@dataclass
class Site:
    """Represents a SentinelOne management site within an account."""

    id: str
    name: str
    accountId: str
    accountName: str
    state: str
    activeLicenses: int
    totalLicenses: int
    createdAt: str
    updatedAt: str
    registrationToken: str
    siteType: str           # "Paid" | "Trial"
    sku: str                # "Complete" | "Control"
    suite: str              # "Complete" | "Core"
    healthStatus: bool      # real API returns bool, not string
    isDefault: bool
    expiration: str | None = None
    unlimitedExpiration: bool = False
    unlimitedLicenses: bool = False
    description: str | None = None
    externalId: str | None = None
    inheritAccountExpiration: bool | None = None
    irFields: str | None = None
    usageType: str | None = None
    creator: str | None = None
    creatorId: str | None = None
    licenses: dict = field(default_factory=lambda: {
        "bundles": [], "modules": [], "settings": [],
    })

    # Internal only — not in real API
    location: str = ""
