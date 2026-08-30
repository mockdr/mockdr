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

    # The 51 members `PUT /tenant/policy` documents, of which this record
    # carried 8. `update_policy` sets what the record has and drops the rest,
    # so a client turning on anti-tampering — or any of 43 other settings —
    # was answered 200, and read back the value it had before. The defaults
    # below are what the answer already carried, so nothing a client reads
    # changes; what changes is that a write to them now sticks.
    #
    # An empty object is completed from the fixture on the way out, exactly
    # as `engines` already is, so these stay one line each rather than a
    # second copy of the fixture.
    agentLoggingOn: bool = False
    agentNotification: bool = False
    agentUiOn: bool = False
    allowRemoteShell: bool = False
    allowUnprotectByApprovedProcess: bool = False
    antiTamperingOn: bool = False
    autoDecommissionOn: bool = False
    autoImmuneOn: bool = False
    driverBlocking: bool = False
    identityOn: bool = False
    informationalAlertsOn: bool = False
    ioc: bool = False
    iocSupported: bool = False
    isDvPolicyPerEventType: bool = False
    logCollectorEnabled: bool = False
    networkProtectionInfra: bool = False
    networkQuarantineOn: bool = False
    removeMacros: bool = False
    removeMacrosMl: bool = False
    researchOn: bool = False
    signedDriverBlockingOn: bool = False
    snapshotsOn: bool = False
    unsignedDriverBlockingOn: bool = False
    autoDecommissionDays: int = 0
    driftDetectionDelayTime: int = 0
    identityReportInterval: int = 0
    identityThrottlingInterval: int = 0
    identityUpdateInterval: int = 0
    autoMitigationAction: str = ""
    identityEndpointReporting: str = "disabled"
    autoFileUpload: dict = field(default_factory=dict)
    dvAttributesPerEventType: dict = field(default_factory=dict)
    forensicsAutoTriggering: dict = field(default_factory=dict)
    identityConfigurationSettings: dict = field(default_factory=dict)
    iocAttributes: dict = field(default_factory=dict)
    remoteOpsForensics: dict = field(default_factory=dict)
    remoteScriptOrchestration: dict = field(default_factory=dict)

    # Server-controlled, and deliberately not settable through the body:
    # who last changed the policy and when it was made.
    createdAt: str = ""
    userId: str = ""
    userFullName: str = ""
