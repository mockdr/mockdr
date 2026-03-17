"""Repository for Microsoft Sentinel entity entities."""
from __future__ import annotations

from domain.sentinel.entity import SentinelEntity
from repository.base import Repository


class SentinelEntityRepository(Repository[SentinelEntity]):
    """In-memory repository for ``SentinelEntity`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the sentinel_entities collection."""
        super().__init__("sentinel_entities")



sentinel_entity_repo = SentinelEntityRepository()
