"""Repository for Microsoft Graph Drive entities."""
from domain.graph.drive import GraphDrive
from repository.base import Repository


class GraphDriveRepository(Repository[GraphDrive]):
    """In-memory repository for ``GraphDrive`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_drives collection."""
        super().__init__("graph_drives")


graph_drive_repo = GraphDriveRepository()
