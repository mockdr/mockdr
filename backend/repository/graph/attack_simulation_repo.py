"""Repository for Microsoft Graph Attack Simulation entities."""
from domain.graph.attack_simulation import GraphAttackSimulation
from repository.base import Repository


class GraphAttackSimulationRepository(Repository[GraphAttackSimulation]):
    """In-memory repository for ``GraphAttackSimulation`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_attack_simulations collection."""
        super().__init__("graph_attack_simulations")


graph_attack_simulation_repo = GraphAttackSimulationRepository()
