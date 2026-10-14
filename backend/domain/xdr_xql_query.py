"""Domain dataclass for Palo Alto Cortex XDR XQL Query entity."""
from dataclasses import dataclass, field


@dataclass
class XdrXqlQuery:
    """A Cortex XDR XQL query execution record."""

    query_id: str
    status: str = "PENDING"  # PENDING / SUCCESS / FAIL, as the wire spells them
    query: str = ""
    results: list[dict] = field(default_factory=list)
    execution_time: int = 0  # epoch ms
    #: Handed out once the result set is too large to answer inline.
    stream_id: str = ""

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.query_id
