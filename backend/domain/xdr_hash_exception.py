"""Domain dataclass for Palo Alto Cortex XDR hash exception entity."""
from dataclasses import dataclass


@dataclass
class XdrHashException:
    """A Cortex XDR hash exception (allowlist or blocklist entry).

    Mirrors the real XDR API structure for hash exceptions used to
    override default file verdicts.
    """

    exception_id: str
    hash: str = ""
    list_type: str = "blocklist"  # blocklist / allowlist
    comment: str = ""
    created_at: int = 0  # epoch ms

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.exception_id
