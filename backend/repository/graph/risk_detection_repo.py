"""Repository for Microsoft Graph Risk Detection entities."""
from domain.graph.risk_detection import GraphRiskDetection
from repository.base import Repository


class GraphRiskDetectionRepository(Repository[GraphRiskDetection]):
    """In-memory repository for ``GraphRiskDetection`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_risk_detections collection."""
        super().__init__("graph_risk_detections")


graph_risk_detection_repo = GraphRiskDetectionRepository()
