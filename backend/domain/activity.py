from dataclasses import dataclass, field
from enum import IntEnum


class ActivityType(IntEnum):
    """Named constants for SentinelOne activity type IDs."""

    PROCESS_EVENT = 2          # Generic process / file event
    USER_SESSION = 6           # Interactive user session started
    ADMIN_NOTE = 10            # SOC / admin note or escalation
    AGENT_CONNECTED = 80       # Agent connected to console / file fetched
    POLICY_UPDATED = 120       # Policy configuration changed
    EXCLUSION_ADDED = 128      # Threat exclusion created
    NETWORK_ISOLATED = 1109    # Agent network isolation applied
    DV_QUERY = 2001            # Deep Visibility query initiated
    POLICY_EVALUATED = 3010    # Policy engine evaluated (protect mode)
    POLICY_DETECT_ONLY = 3011  # Policy engine evaluated (detect / monitor-only mode)


@dataclass
class Activity:
    """Represents a SentinelOne audit activity log entry."""

    id: str
    activityType: int
    primaryDescription: str
    createdAt: str
    updatedAt: str
    activityUuid: str = ""
    description: str | None = None
    secondaryDescription: str | None = None
    agentId: str | None = None
    agentUpdatedVersion: str | None = None
    threatId: str | None = None
    userId: str | None = None
    siteId: str | None = None
    siteName: str | None = None
    groupId: str | None = None
    groupName: str | None = None
    accountId: str | None = None
    accountName: str | None = None
    hash: str | None = None
    osFamily: str | None = None
    comments: str | None = None
    data: dict = field(default_factory=dict)
