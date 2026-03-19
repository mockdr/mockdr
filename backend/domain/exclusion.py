from dataclasses import dataclass, field


@dataclass
class Exclusion:
    """Represents a SentinelOne threat exclusion rule."""

    id: str
    type: str               # "path" | "white_hash" | "certificate" | "browser"
    value: str
    osType: str
    mode: str               # "disable_all_monitors" | "suppress" | etc.
    source: str             # "user" | "api" | "import"
    createdAt: str
    updatedAt: str
    userId: str
    userName: str
    scopeName: str          # e.g. "Global" | site name
    scopePath: str          # e.g. "Global" | "Global / Acme / Site"
    actions: list = field(default_factory=list)         # ["upload", "detect", ...]
    description: str | None = None
    applicationName: str | None = None
    pathExclusionType: str | None = None             # "file" | "directory" | "subfolders"
    notRecommended: str = "NONE"
    imported: bool = False
    inAppInventory: bool = False
    includeChildren: bool = False
    includeParents: bool = False
    inject: bool = False
    scope: dict = field(default_factory=lambda: {"tenant": True})
    # ^ real API: {"tenant": True} for global, {"siteId": "..."} for site scope

    # Internal only — used for filtering
    siteId: str = ""
