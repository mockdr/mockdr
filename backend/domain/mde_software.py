"""Domain dataclass for Microsoft Defender for Endpoint Software (TVM) entity."""
from dataclasses import dataclass


@dataclass
class MdeSoftware:
    """A software entry from MDE Threat & Vulnerability Management.

    The ``softwareId`` uses the MDE format: ``vendor-_-product``.
    """

    softwareId: str  # noqa: N815 — "microsoft-_-windows_10" format
    name: str = ""
    vendor: str = ""
    version: str = ""
    weaknesses: int = 0
    publicExploit: bool = False  # noqa: N815
    activeAlert: bool = False  # noqa: N815
    exposedMachines: int = 0  # noqa: N815
    impactScore: float = 0.0  # noqa: N815

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.softwareId
