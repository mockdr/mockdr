from dataclasses import dataclass, field


@dataclass
class DVQuery:
    """Represents a Deep Visibility query and its results."""

    id: str
    query: str
    fromDate: str
    toDate: str
    status: str       # RUNNING | FINISHED | CANCELLED
    createdAt: str
    events: list = field(default_factory=list)
