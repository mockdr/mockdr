"""Repository for Microsoft Graph Directory Role entities."""
from domain.graph.directory_role import GraphDirectoryRole
from repository.base import Repository


class GraphDirectoryRoleRepository(Repository[GraphDirectoryRole]):
    """In-memory repository for ``GraphDirectoryRole`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_directory_roles collection."""
        super().__init__("graph_directory_roles")


graph_directory_role_repo = GraphDirectoryRoleRepository()
