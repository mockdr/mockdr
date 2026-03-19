"""Domain dataclass for Palo Alto Cortex XDR Script entity."""
from dataclasses import dataclass


@dataclass
class XdrScript:
    """A Cortex XDR script available for execution on endpoints."""

    script_id: str
    name: str = ""
    description: str = ""
    script_type: str = "python"  # python / powershell / shell
    is_high_risk: bool = False
    modification_date: int = 0  # epoch ms
    created_by: str = ""

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.script_id
