"""Domain dataclass for Palo Alto Cortex XDR Endpoint entity."""
from dataclasses import dataclass, field

#: How Cortex spells an endpoint's isolation state in ``is_isolated``
#: (XSOAR CortexXDR test_data get_endpoints.json carries
#: ``AGENT_UNISOLATED``; CoreIRApiModule's isolate/unisolate commands branch
#: on all four). Isolation is asynchronous: an endpoint is pending until its
#: agent acknowledges the request.
AGENT_ISOLATED = "AGENT_ISOLATED"
AGENT_UNISOLATED = "AGENT_UNISOLATED"
AGENT_PENDING_ISOLATION = "AGENT_PENDING_ISOLATION"
AGENT_PENDING_ISOLATION_CANCELLATION = "AGENT_PENDING_ISOLATION_CANCELLATION"


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

    is_isolated: str = AGENT_UNISOLATED  # one of the AGENT_* states above
    isolated_date: int | None = None
    #: When the pending isolation state was entered (epoch ms) — mockdr's own
    #: bookkeeping for settling it, never served.
    isolation_requested_at: int | None = None

    group_name: list[str] = field(default_factory=list)
    operational_status: str = "fully_protected"
    scan_status: str = "none"

    users: list[str] = field(default_factory=list)

    #: Cortex serves both of these on every endpoint, and both are filter
    #: fields — `dist_name` narrows by installation package, `public_ip_list`
    #: by the address the endpoint is seen from. They existed only as fixture
    #: defaults, so the two filters accepted a value and answered nothing.
    installation_package: str = ""
    public_ip: list[str] = field(default_factory=list)

    #: The tags assigned through ``/tags/agents/assign/``. Cortex serves them
    #: in ``endpointTags``, which its reference example types as a string, so
    #: the read side joins these with commas. Kept as a list here because the
    #: assign and remove routes work one tag at a time.
    endpoint_tags: list[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.endpoint_id
