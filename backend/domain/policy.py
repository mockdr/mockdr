from dataclasses import dataclass, field


@dataclass
class Policy:
    """Represents a SentinelOne protection policy for a site or group."""

    id: str
    scopeId: str
    scopeType: str
    mitigationMode: str
    mitigationModeSuspicious: str
    monitorOnWrite: bool
    monitorOnExecute: bool
    blockOnWrite: bool
    blockOnExecute: bool
    scanNewAgents: bool
    scanOnWritten: bool
    autoMitigate: bool
    updatedAt: str
    engines: dict = field(default_factory=dict)
    agentUi: dict = field(default_factory=dict)
    firewall: dict = field(default_factory=dict)
