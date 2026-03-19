from dataclasses import dataclass


@dataclass
class Group:
    """Represents a SentinelOne agent group within a site."""

    id: str
    name: str
    siteId: str
    type: str
    createdAt: str
    updatedAt: str
    totalAgents: int
    isDefault: bool
    rank: int | None = None
    inherits: bool = True
    description: str | None = None
    filterId: str | None = None
    filterName: str | None = None
    registrationToken: str = ""
    creator: str | None = None
    creatorId: str | None = None

    # Internal only — not in real API
    siteName: str = ""
    accountId: str = ""
    accountName: str = ""
