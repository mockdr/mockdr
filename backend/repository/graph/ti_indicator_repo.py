"""Repository for Microsoft Graph Threat Intelligence Indicator entities."""
from domain.graph.ti_indicator import GraphTiIndicator
from repository.base import Repository


class GraphTiIndicatorRepository(Repository[GraphTiIndicator]):
    """In-memory repository for ``GraphTiIndicator`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_ti_indicators collection."""
        super().__init__("graph_ti_indicators")


graph_ti_indicator_repo = GraphTiIndicatorRepository()
