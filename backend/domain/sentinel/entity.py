"""Domain dataclass for Microsoft Sentinel Entity."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SentinelEntity:
    """A Microsoft Sentinel entity record.

    Maps 1:1 to real Sentinel ``/entities`` API fields.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    entity_id: str
    kind: str = "Host"
    # Account / Host / Ip / File / Process / Url / FileHash / Malware
    # RegistryKey / CloudApplication

    # ── Properties ────────────────────────────────────────────────────────────
    properties: dict[str, object] = field(default_factory=dict)

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.entity_id
