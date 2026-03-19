from dataclasses import dataclass, field


@dataclass
class FirewallRule:
    """Represents a SentinelOne firewall control rule."""

    id: str
    name: str
    description: str
    status: str         # "Enabled" | "Disabled"
    action: str         # "Allow" | "Block"
    direction: str      # "inbound" | "outbound" | "both"
    order: int
    createdAt: str
    updatedAt: str
    osType: str         # "windows" | "macos" | "linux"
    osTypes: list = field(default_factory=lambda: ["windows"])
    protocol: str | None = None
    ruleCategory: str = "firewall"
    scope: str = "global"           # "global" | "site" | "group"
    scopeId: str | None = None
    editable: bool = True
    tag: str = ""
    tagIds: list = field(default_factory=list)
    tagNames: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    creator: str | None = None
    creatorId: str | None = None

    # Port / host fields use object format: {"type": "any"|"specific", "values": [...]}
    localPort: dict = field(default_factory=lambda: {"type": "any", "values": []})
    remotePort: dict = field(default_factory=lambda: {"type": "any", "values": []})
    localHost: dict = field(default_factory=lambda: {"type": "any", "values": []})
    remoteHost: dict = field(default_factory=lambda: {"type": "any", "values": []})
    remoteHosts: list = field(default_factory=lambda: [{"type": "any", "values": []}])
    application: dict = field(default_factory=lambda: {"type": "any", "values": []})
    location: dict = field(default_factory=lambda: {"type": "all", "values": []})

    # Internal only — used for filtering
    siteId: str = ""
