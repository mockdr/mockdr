"""Domain dataclass for CrowdStrike Falcon Custom IOC entities."""
from dataclasses import dataclass, field


@dataclass
class CsIoc:
    """A CrowdStrike Falcon custom indicator of compromise (IOC).

    Field names match the real CrowdStrike Falcon API exactly (snake_case).
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    id: str

    # ── Indicator ─────────────────────────────────────────────────────────────
    type: str = ""
    value: str = ""
    source: str = ""

    # ── Action / Severity ─────────────────────────────────────────────────────
    action: str = "no_action"
    severity: str = "informational"
    description: str = ""

    # ── Scope ─────────────────────────────────────────────────────────────────
    platforms: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    applied_globally: bool = True
    host_groups: list[str] = field(default_factory=list)

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    expiration: str = ""
    expired: bool = False
    deleted: bool = False

    # ── Mobile ────────────────────────────────────────────────────────────────
    mobile_action: str = ""

    # ── Audit ─────────────────────────────────────────────────────────────────
    created_on: str = ""
    created_by: str = ""
    modified_on: str = ""
    modified_by: str = ""

    # ── Parent / Metadata ─────────────────────────────────────────────────────
    from_parent: bool = False
    metadata: dict = field(default_factory=dict)
