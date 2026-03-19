"""Repository for Microsoft Defender for Endpoint Machine entities."""
from domain.mde_machine import MdeMachine
from repository.base import Repository


class MdeMachineRepository(Repository[MdeMachine]):
    """In-memory repository for ``MdeMachine`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the mde_machines collection."""
        super().__init__("mde_machines")


mde_machine_repo = MdeMachineRepository()
