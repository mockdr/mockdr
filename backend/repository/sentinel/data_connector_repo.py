"""Repository for Microsoft Sentinel data connector entities."""
from __future__ import annotations

from domain.sentinel.data_connector import SentinelDataConnector
from repository.base import Repository


class SentinelDataConnectorRepository(Repository[SentinelDataConnector]):
    """In-memory repository for ``SentinelDataConnector`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the sentinel_data_connectors collection."""
        super().__init__("sentinel_data_connectors")



sentinel_data_connector_repo = SentinelDataConnectorRepository()
