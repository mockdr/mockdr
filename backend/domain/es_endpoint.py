"""Domain dataclass for Elastic Security endpoint entities."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EsEndpoint:
    """An Elastic Security managed endpoint.

    Field names use snake_case to match the real Elastic API format.
    The ``id`` property aliases ``agent_id`` so the generic Repository[T]
    pattern works unchanged.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    agent_id: str
    hostname: str

    # ── Network ───────────────────────────────────────────────────────────────
    host_ip: list[str] = field(default_factory=list)
    host_mac: list[str] = field(default_factory=list)

    # ── OS ────────────────────────────────────────────────────────────────────
    host_os_name: str = ""
    host_os_version: str = ""
    host_os_full: str = ""
    host_architecture: str = "x86_64"

    # ── Agent ─────────────────────────────────────────────────────────────────
    agent_version: str = ""
    agent_status: str = "online"
    agent_type: str = "endpoint"

    # ── Policy ────────────────────────────────────────────────────────────────
    policy_id: str = ""
    policy_name: str = ""
    policy_revision: int = 1

    # ── Timestamps ────────────────────────────────────────────────────────────
    enrolled_at: str = ""
    last_checkin: str = ""

    # ── Isolation ─────────────────────────────────────────────────────────────
    isolation_status: str = "normal"

    # ── Meta ──────────────────────────────────────────────────────────────────
    metadata: dict = field(default_factory=dict)

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.agent_id
