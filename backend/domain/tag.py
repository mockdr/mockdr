"""Domain dataclass for scoped endpoint tags."""
from dataclasses import dataclass


@dataclass
class Tag:
    """A scoped tag definition that can be assigned to agents.

    Tags exist independently of agents and are managed via ``/tag-manager``.
    They are scoped to a level in the hierarchy (global -> account -> site -> group).

    ``endpointsInCurrentScope``, ``totalEndpoints``, and ``totalExclusions`` are
    computed at query time — they are not persisted on the domain object.
    """

    id: str
    key: str
    value: str
    type: str = "agents"
    description: str = ""
    scopeId: str = ""
    scopeLevel: str = "global"
    scopePath: str = "Global"
    createdAt: str = ""
    updatedAt: str = ""
    createdBy: str = ""
    updatedBy: str = ""
    createdById: str = ""
    updatedById: str = ""
    allowEdit: bool = True
