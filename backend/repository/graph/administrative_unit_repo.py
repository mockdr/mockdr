"""Repository for Microsoft Graph Administrative Unit entities."""
from domain.graph.administrative_unit import GraphAdministrativeUnit
from repository.base import Repository


class GraphAdministrativeUnitRepository(Repository[GraphAdministrativeUnit]):
    """In-memory repository for ``GraphAdministrativeUnit`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_administrative_units collection."""
        super().__init__("graph_administrative_units")


graph_admin_unit_repo = GraphAdministrativeUnitRepository()
