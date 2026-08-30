from dataclasses import dataclass


@dataclass
class Account:
    """Represents a SentinelOne management account."""

    id: str
    name: str
    createdAt: str
    updatedAt: str
    state: str
    numberOfSites: int
    numberOfAgents: int
    activeAgents: int
    numberOfUsers: int
    accountType: str
    isDefault: bool
    expiration: str | None = None
    # Declared on the account response with enums of their own; nothing set
    # them, so the answer carried the swagger's example values, identical for
    # every account and matched by no filter.
    billingMode: str = "subscription"
    usageType: str = "customer"
    totalLicenses: int = 0
