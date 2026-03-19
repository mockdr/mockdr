"""Domain dataclass for Palo Alto Cortex XDR Endpoint entity."""
from dataclasses import dataclass, field


@dataclass
class XdrEndpoint:
    """A Cortex XDR managed endpoint.

    Maps 1:1 to real Cortex XDR ``/public_api/v1/endpoints/get_endpoint`` fields.
    """

    endpoint_id: str
    endpoint_name: str = ""
    endpoint_type: str = "desktop"  # desktop / laptop / server
    endpoint_status: str = "connected"  # connected / disconnected / lost / uninstalled

    os_type: str = "windows"  # windows / linux / macos
    ip: list[str] = field(default_factory=list)

    domain: str = ""
    alias: str = ""
    first_seen: int = 0  # epoch ms
    last_seen: int = 0  # epoch ms
    install_date: int = 0  # epoch ms

    content_version: str = ""
    endpoint_version: str = ""

    is_isolated: str = "unisolated"  # isolated / unisolated
    isolated_date: int | None = None

    group_name: list[str] = field(default_factory=list)
    operational_status: str = "fully_protected"
    scan_status: str = "none"

    users: list[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.endpoint_id
