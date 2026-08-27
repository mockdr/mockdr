"""Domain dataclass for Palo Alto Cortex XDR Action (response action) entity."""
from dataclasses import dataclass


@dataclass
class XdrAction:
    """A Cortex XDR response action record."""

    action_id: str
    action_type: str = "scan"
    # isolate / unisolate / scan / file_retrieval / script_run / quarantine / restore

    status: str = "completed"
    # pending / in_progress / completed / failed / canceled

    endpoint_id: str = ""
    #: Every endpoint this action covers. Cortex takes a `filters` block on
    #: most action routes and answers one `action_id` for the set, and
    #: `get_action_status` keys its answer by endpoint — so an action that
    #: named only one of them left the others out of the status a playbook
    #: polls.
    endpoint_ids: list[str] | None = None
    result: dict | None = None
    creation_time: int = 0  # epoch ms

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.action_id
