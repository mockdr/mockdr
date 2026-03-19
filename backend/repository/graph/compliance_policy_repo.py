"""Repository for Microsoft Graph Compliance Policy entities."""
from domain.graph.compliance_policy import GraphCompliancePolicy
from repository.base import Repository


class GraphCompliancePolicyRepository(Repository[GraphCompliancePolicy]):
    """In-memory repository for ``GraphCompliancePolicy`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_compliance_policies collection."""
        super().__init__("graph_compliance_policies")


graph_compliance_policy_repo = GraphCompliancePolicyRepository()
