"""Repository for Microsoft Graph Threat Assessment Request entities."""
from domain.graph.threat_assessment import GraphThreatAssessment
from repository.base import Repository


class GraphThreatAssessmentRepository(Repository[GraphThreatAssessment]):
    """In-memory repository for ``GraphThreatAssessment`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_threat_assessments collection."""
        super().__init__("graph_threat_assessments")


graph_threat_assessment_repo = GraphThreatAssessmentRepository()
