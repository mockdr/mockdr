"""Repository for Microsoft Graph SharePoint Site entities."""
from domain.graph.sharepoint_site import GraphSharePointSite
from repository.base import Repository


class GraphSharePointSiteRepository(Repository[GraphSharePointSite]):
    """In-memory repository for ``GraphSharePointSite`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_sharepoint_sites collection."""
        super().__init__("graph_sharepoint_sites")


graph_sharepoint_site_repo = GraphSharePointSiteRepository()
