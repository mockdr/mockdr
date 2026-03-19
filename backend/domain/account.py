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
