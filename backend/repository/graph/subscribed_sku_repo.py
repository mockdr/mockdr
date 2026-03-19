"""Repository for Microsoft Graph Subscribed SKU entities."""
from domain.graph.subscribed_sku import GraphSubscribedSku
from repository.base import Repository


class GraphSubscribedSkuRepository(Repository[GraphSubscribedSku]):
    """In-memory repository for ``GraphSubscribedSku`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_subscribed_skus collection."""
        super().__init__("graph_subscribed_skus")


graph_subscribed_sku_repo = GraphSubscribedSkuRepository()
