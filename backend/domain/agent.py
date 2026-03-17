from dataclasses import dataclass, field


@dataclass
class Agent:
    """Represents a SentinelOne managed endpoint agent."""

    # ── Identity ──────────────────────────────────────────────────────────────
    id: str
    uuid: str
    computerName: str
    externalId: str
    serialNumber: str

    # ── Account / Site / Group ────────────────────────────────────────────────
    accountId: str
    accountName: str
    siteId: str
    siteName: str
    groupId: str
    groupName: str
    groupIp: str

    # ── OS ────────────────────────────────────────────────────────────────────
    osName: str
    osType: str
    osRevision: str
    osArch: str
    osUsername: str | None
    osStartTime: str | None

    # ── Hardware / Machine ────────────────────────────────────────────────────
    machineType: str
    modelName: str
    machineSid: str
    cpuId: str
    cpuCount: int
    coreCount: int
    totalMemory: int

    # ── Agent ─────────────────────────────────────────────────────────────────
    agentVersion: str
    installerType: str
    registeredAt: str
    createdAt: str
    updatedAt: str
    lastActiveDate: str
    licenseKey: str
    isActive: bool
    isDecommissioned: bool
    isPendingUninstall: bool
    isUninstalled: bool
    isUpToDate: bool
    isAdConnector: bool
    isHyperAutomate: bool | None

    # ── Network ───────────────────────────────────────────────────────────────
    externalIp: str
    lastIpToMgmt: str
    domain: str
    networkStatus: str
    networkQuarantineEnabled: bool
    networkInterfaces: list = field(default_factory=list)
    locationEnabled: bool = True
    locationType: str = "fallback"
    locations: list = field(default_factory=list)

    # ── Decommission ───────────────────────────────────────────────────────────
    decommissionedAt: str | None = None

    # ── Security state ────────────────────────────────────────────────────────
    infected: bool = False
    activeThreats: int = 0
    detectionState: str = "full_mode"
    mitigationMode: str = "protect"
    mitigationModeSuspicious: str = "detect"
    activeProtection: list = field(default_factory=list)
    threatRebootRequired: bool = False
    firewallEnabled: bool = True
    encryptedApplications: bool = False
    appsVulnerabilityStatus: str = "none"
    showAlertIcon: bool = False
    missingPermissions: list = field(default_factory=list)
    userActionsNeeded: list = field(default_factory=list)

    # ── Scan ──────────────────────────────────────────────────────────────────
    scanStatus: str = "finished"
    scanFinishedAt: str | None = None
    scanAbortedAt: str | None = None
    scanStartedAt: str | None = None
    lastSuccessfulScanDate: str | None = None
    fullDiskScanLastUpdatedAt: str | None = None
    firstFullModeTime: str | None = None

    # ── Ranger ────────────────────────────────────────────────────────────────
    rangerStatus: str = "Enabled"
    rangerVersion: str = "21.11.0.171"

    # ── Remote / Shell ────────────────────────────────────────────────────────
    allowRemoteShell: bool = True
    inRemoteShellSession: bool = False
    remoteProfilingState: str = "disabled"
    remoteProfilingStateExpiration: str | None = None

    # ── Proxy ─────────────────────────────────────────────────────────────────
    proxyStates: dict = field(default_factory=lambda: {"console": False, "deepVisibility": False})

    # ── Cloud / Container ─────────────────────────────────────────────────────
    cloudProviders: dict = field(default_factory=dict)
    hasContainerizedWorkload: bool = False
    containerizedWorkloadCounts: dict | None = None

    # ── Console migration ─────────────────────────────────────────────────────
    consoleMigrationStatus: str = "N/A"

    # ── Operational state ─────────────────────────────────────────────────────
    operationalState: str = "na"
    operationalStateExpiration: str | None = None

    # ── Storage ───────────────────────────────────────────────────────────────
    storageName: str | None = None
    storageType: str | None = None

    # ── Tags ──────────────────────────────────────────────────────────────────
    tags: dict = field(default_factory=lambda: {"sentinelone": []})

    # ── Policy / Group update timestamps ────────────────────────────────────
    groupUpdatedAt: str | None = None
    policyUpdatedAt: str | None = None

    # ── Active Directory ──────────────────────────────────────────────────────
    activeDirectory: dict = field(default_factory=dict)

    # ── Internal-only (not in real S1 API — stripped from /agents responses) ──
    passphrase: str = ""
    lastLoggedInUserName: str = ""  # NOTE: This IS part of the real S1 API
    localIp: str = ""
    installedAt: str = ""
    isInfected: bool = False
    agentLicenseType: str = "y3"
    cpuUsage: float = 0.0
    memoryUsage: int = 0
