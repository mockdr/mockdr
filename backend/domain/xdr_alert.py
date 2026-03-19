"""Domain dataclass for Palo Alto Cortex XDR Alert entity."""
from dataclasses import dataclass, field


@dataclass
class XdrAlert:
    """A Cortex XDR alert record.

    Maps 1:1 to real Cortex XDR ``/public_api/v1/alerts/get_alerts`` fields.
    """

    alert_id: str
    internal_id: str = ""
    severity: str = "medium"  # low / medium / high / critical
    category: str = ""
    action: str = ""
    action_pretty: str = ""
    description: str = ""
    name: str = ""

    source: str = "XDR Agent"  # BIOC / Correlation / IOC / XDR Agent
    detection_timestamp: int = 0  # epoch ms

    endpoint_id: str = ""
    host_name: str = ""
    host_ip: list[str] = field(default_factory=list)

    user_name: str = ""
    mitre_technique_id_and_name: str = ""
    mitre_tactic_id_and_name: str = ""

    starred: bool = False
    event_type: str = ""

    is_whitelisted: bool = False
    alert_action_status: str = "detected"  # detected / prevented / blocked

    # Link to parent incident (used by repo helper)
    incident_id: str = ""

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.alert_id
