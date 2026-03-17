"""Domain dataclass for Microsoft Sentinel Data Connector entity."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SentinelDataConnector:
    """A Microsoft Sentinel data connector record.

    Maps 1:1 to real Sentinel ``/dataConnectors`` API fields.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    connector_id: str
    name: str = ""
    kind: str = ""
    tenant_id: str = "mockdr-tenant"

    # ── State ─────────────────────────────────────────────────────────────────
    data_types_state: str = "Enabled"

    # ── Versioning ────────────────────────────────────────────────────────────
    etag: str = ""

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.connector_id
