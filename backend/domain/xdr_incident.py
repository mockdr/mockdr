"""Domain dataclass for Palo Alto Cortex XDR Incident entity."""
from dataclasses import dataclass, field


@dataclass
class XdrIncident:
    """A Cortex XDR incident record.

    Maps 1:1 to real Cortex XDR ``/public_api/v1/incidents/get_incidents`` fields.
    """

    incident_id: str
    description: str
    alert_count: int = 0
    severity: str = "medium"  # low / medium / high / critical

    status: str = "new"
    # new / under_investigation / resolved_known_issue / resolved_duplicate
    # resolved_false_positive / resolved_true_positive / resolved_other

    assigned_user_mail: str = ""
    assigned_user_pretty_name: str = ""

    creation_time: int = 0  # epoch ms
    modification_time: int = 0  # epoch ms
    detection_time: str = ""

    low_severity_alert_count: int = 0
    med_severity_alert_count: int = 0
    high_severity_alert_count: int = 0

    hosts: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    incident_sources: list[str] = field(default_factory=list)

    rule_based_score: int = 0
    manual_score: int = 0

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.incident_id
