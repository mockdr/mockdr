"""Repository for Microsoft Defender for Endpoint Machine Action entities."""
from domain.mde_machine_action import MdeMachineAction
from repository.base import Repository


class MdeMachineActionRepository(Repository[MdeMachineAction]):
    """In-memory repository for ``MdeMachineAction`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the mde_machine_actions collection."""
        super().__init__("mde_machine_actions")

    def get_by_machine_id(self, machine_id: str) -> list[MdeMachineAction]:
        """Return all actions associated with the given machine ID."""
        return [a for a in self.list_all() if a.machineId == machine_id]


mde_machine_action_repo = MdeMachineActionRepository()
