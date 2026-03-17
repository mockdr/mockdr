"""Domain dataclass for a Splunk Enterprise Security notable event."""
from dataclasses import dataclass, field


@dataclass
class NotableEvent:
    """An ES notable event stored in the ``notable`` index.

    Contains all fields that XSOAR SplunkPy expects when fetching incidents.
    """

    event_id: str
    rule_name: str = ""
    rule_title: str = ""
    rule_id: str = ""
    search_name: str = ""
    security_domain: str = "endpoint"
    severity: str = "medium"
    urgency: str = "medium"
    status: str = "1"          # 1=New 2=InProgress 3=Pending 4=Resolved 5=Closed
    status_label: str = "New"
    owner: str = "unassigned"
    src: str = ""
    dest: str = ""
    user: str = ""
    description: str = ""
    drilldown_search: str = ""
    time: str = ""             # epoch seconds string
    _time: str = ""            # alias for time
    info_min_time: str = ""
    info_max_time: str = ""
    comment: str = ""

    # Status history for audit trail
    status_history: list[dict[str, str]] = field(default_factory=list)

    # Link back to originating EDR vendor + entity
    edr_vendor: str = ""
    edr_entity_id: str = ""

    @property
    def id(self) -> str:
        """Primary identifier expected by ``Repository[T]``."""
        return self.event_id
