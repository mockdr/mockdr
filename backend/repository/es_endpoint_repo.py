"""Repository for Elastic Security endpoint entities."""
from __future__ import annotations

from domain.es_endpoint import EsEndpoint
from repository.base import Repository


class EsEndpointRepository(Repository[EsEndpoint]):
    """In-memory repository for ``EsEndpoint`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the es_endpoints collection."""
        super().__init__("es_endpoints")



es_endpoint_repo = EsEndpointRepository()
