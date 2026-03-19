from dataclasses import dataclass, field


@dataclass
class Alert:
    """Represents a SentinelOne cloud-detection (STAR) alert.

    Top-level structure matches the real S1 /cloud-detection/alerts API response.
    Primary key is ``alertInfo.alertId`` — there is no top-level ``id`` field.
    """

    # alertInfo — core alert metadata (verdict, status, timing, detection detail)
    alertInfo: dict = field(default_factory=dict)

    # ruleInfo — the STAR rule that triggered this alert
    ruleInfo: dict = field(default_factory=dict)

    # sourceProcessInfo — the process that caused the alert
    sourceProcessInfo: dict = field(default_factory=dict)

    # agentDetectionInfo — agent detection context (uuid, version, site)
    agentDetectionInfo: dict = field(default_factory=dict)

    # agentRealtimeInfo — agent state at detection time (id, name, os, version)
    agentRealtimeInfo: dict | None = None

    # containerInfo / kubernetesInfo — populated for container workloads only
    containerInfo: dict | None = None
    kubernetesInfo: dict | None = None

    # sourceParentProcessInfo / targetProcessInfo — populated when available
    sourceParentProcessInfo: dict | None = None
    targetProcessInfo: dict | None = None

    @property
    def id(self) -> str:
        """Return the alert's primary key for the generic Repository pattern."""
        return str(self.alertInfo.get("alertId", ""))
