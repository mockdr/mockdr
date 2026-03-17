/** S1 API paginated list response envelope (after axios interceptor unwraps response.data). */
export interface PaginatedResponse<T> {
  data: T[]
  pagination: {
    totalItems: number
    nextCursor: string | null
  }
}

/** S1 API single-record response envelope. */
export interface SingleResponse<T> {
  data: T
}

/** S1 API action response. */
export interface ActionResponse {
  data: { affected: number }
}

// ── Agent types ──────────────────────────────────────────────────────────────

export interface NetworkInterface {
  id: string
  name: string
  inet: string[]
  inet6: string[]
  physical: string
  gatewayIp: string | null
  gatewayMacAddress: string | null
}

export interface ProxyStates {
  console: boolean
  deepVisibility: boolean
}

export interface AgentTag {
  id: string
  key: string
  value: string
}

export interface ActiveDirectoryInfo {
  computerDistinguishedName: string | null
  lastUserDistinguishedName: string | null
  userPrincipalName: string | null
  computerMemberOf: string[]
  lastUserMemberOf: string[]
}

/** SentinelOne agent record as returned by GET /agents (internal fields stripped). */
export interface Agent {
  id: string
  uuid: string
  computerName: string
  externalId: string
  serialNumber: string
  accountId: string
  accountName: string
  siteId: string
  siteName: string
  groupId: string
  groupName: string
  groupIp: string | null
  osName: string
  osType: 'windows' | 'macos' | 'linux'
  osRevision: string
  osArch: string
  osUsername: string | null
  osStartTime: string | null
  machineType: string
  modelName: string | null
  machineSid: string | null
  cpuId: string | null
  cpuCount: number | null
  coreCount: number | null
  totalMemory: number | null
  agentVersion: string
  installerType: string
  registeredAt: string
  createdAt: string
  updatedAt: string
  lastActiveDate: string
  licenseKey: string
  isActive: boolean
  isDecommissioned: boolean
  isPendingUninstall: boolean
  isUninstalled: boolean
  isUpToDate: boolean
  isAdConnector: boolean
  isHyperAutomate: boolean | null
  externalIp: string
  /** Management-facing IP — use instead of the stripped localIp field. */
  lastIpToMgmt: string
  domain: string | null
  networkStatus: 'connected' | 'disconnected' | 'not_applicable'
  networkQuarantineEnabled: boolean
  networkInterfaces: NetworkInterface[]
  locationEnabled: boolean
  locationType: string | null
  locations: unknown[]
  /** True if the agent has active threats. Use instead of the stripped isInfected field. */
  infected: boolean
  activeThreats: number
  detectionState: string
  mitigationMode: string
  mitigationModeSuspicious: string
  activeProtection: unknown[]
  threatRebootRequired: boolean
  firewallEnabled: boolean
  encryptedApplications: boolean
  appsVulnerabilityStatus: string | null
  showAlertIcon: boolean
  missingPermissions: unknown[]
  userActionsNeeded: unknown[]
  scanStatus: string
  scanFinishedAt: string | null
  scanAbortedAt: string | null
  scanStartedAt: string | null
  lastSuccessfulScanDate: string | null
  fullDiskScanLastUpdatedAt: string | null
  firstFullModeTime: string | null
  rangerStatus: string
  rangerVersion: string | null
  allowRemoteShell: boolean
  inRemoteShellSession: boolean
  remoteProfilingState: string
  remoteProfilingStateExpiration: string | null
  proxyStates: ProxyStates
  cloudProviders: Record<string, string>
  hasContainerizedWorkload: boolean
  containerizedWorkloadCounts: null
  consoleMigrationStatus: string
  operationalState: string
  operationalStateExpiration: string | null
  storageName: string | null
  storageType: string | null
  tags: { sentinelone: AgentTag[] }
  activeDirectory: ActiveDirectoryInfo | null
  lastLoggedInUserName: string
}

// ── Threat types ─────────────────────────────────────────────────────────────

/** Contents of the threatInfo nested dict in a SentinelOne threat record. */
export interface ThreatInfo {
  threatId: string
  threatName: string
  classification: string
  classificationSource: string
  confidenceLevel: string
  mitigationStatus: string
  mitigationStatusDescription: string | null
  incidentStatus: string
  incidentStatusDescription: string | null
  analystVerdict: string
  analystVerdictDescription: string | null
  sha1: string
  sha256: string | null
  md5: string | null
  fileName: string
  filePath: string
  fileSize: number | null
  initiatedBy: string | null
  storylineId: string | null
  createdAt: string
  updatedAt: string
  resolved: boolean
  engines: string[]
  maliciousGroupId: string | null
  detectionType: string
  reachedEventsLimit: boolean
}

/** Agent state captured at detection time. */
export interface AgentDetectionInfo {
  siteId: string
  siteName: string
  groupId: string
  groupName: string
  accountId: string
  accountName: string
  agentVersion: string
  agentOsName: string
  agentOsRevision: string | null
  agentIpV4: string
  agentIpV6: string | null
  externalIp: string
  agentDomain: string | null
  agentDetectionState: string
  agentLastLoggedInUserName: string | null
  agentComputerName: string
  agentMitigationMode: string
  cloudProviders: Record<string, string>
}

/** Live agent state at time of API call. */
export interface AgentRealtimeInfo {
  agentId: string
  agentVersion: string
  agentOsRevision: string | null
  agentOsName: string
  groupId: string
  groupName: string
  siteId: string
  siteName: string
  accountId: string
  accountName: string
  agentIsActive: boolean
  agentIsDecommissioned: boolean
  agentInfected: boolean
  agentIsUpToDate: boolean
  agentMitigationMode: string
  agentNetworkStatus: string
  networkInterfaces: NetworkInterface[]
  scanStatus: string
  operationalState: string
  rebootRequired: boolean
  agentComputerName: string
  agentMachineType: string
  agentDomain: string | null
  agentIpV4: string
  agentIpV6: string | null
  agentLastLoggedInUserName: string | null
  rangerStatus: string
  userActionsNeeded: string[]
  firewallEnabled: boolean
  allowRemoteShell: boolean
  appsVulnerabilityStatus: string | null
}

/** Full SentinelOne threat record as returned by GET /threats. */
export interface ThreatRecord {
  id: string
  threatInfo: ThreatInfo
  agentDetectionInfo: AgentDetectionInfo
  agentRealtimeInfo: AgentRealtimeInfo
  indicators: unknown[]
  /** Top-level mitigationStatus list (distinct from threatInfo.mitigationStatus string). */
  mitigationStatus: unknown[]
  whiteningOptions: unknown[]
  containerInfo: Record<string, unknown>
  ecsInfo: Record<string, unknown>
  kubernetesInfo: Record<string, unknown>
}

// ── Alert types ───────────────────────────────────────────────────────────────

export interface Alert {
  alertInfo: {
    alertId: string
    createdAt: string
    updatedAt: string
    incidentStatus: string
    analystVerdict: string
    source: string
  }
  ruleInfo: {
    id: string
    name: string
    severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'
    description: string | null
  }
  agentRealtimeInfo: {
    agentComputerName: string | null
    id: string | null
  }
  sourceProcessInfo: {
    storyline: string | null
  } | null
}

// ── Site types ────────────────────────────────────────────────────────────────

export interface AllSitesInfo {
  activeLicenses: number
  totalLicenses: number
}

export interface Site {
  id: string
  name: string
  accountId: string
  accountName: string
  state: string
  siteType: string
  suite?: string
  sku?: string
  description?: string | null
  unlimitedLicenses?: boolean
  isDefault?: boolean
  activeLicenses: number | null
  totalLicenses: number | null
  createdAt: string
  updatedAt: string
}

/** Special envelope returned by GET /sites. */
export interface SitesListResponse {
  data: {
    allSites: AllSitesInfo
    sites: Site[]
  }
  pagination: {
    totalItems: number
    nextCursor: string | null
  }
}

// ── Group types ───────────────────────────────────────────────────────────────

export interface Group {
  id: string
  name: string
  siteId: string
  siteName: string
  type: string
  totalAgents: number
  isDefault: boolean
  description?: string | null
  inherits?: boolean
  createdAt: string
  updatedAt: string
}

// ── Account types ─────────────────────────────────────────────────────────────

export interface Account {
  id: string
  name: string
  state: string
  accountType: string
  numberOfSites: number
  numberOfAgents: number
  activeAgents: number
  numberOfUsers: number
  isDefault: boolean
  createdAt: string
  updatedAt: string
  expiration: string | null
}

// ── User types ────────────────────────────────────────────────────────────────

export interface User {
  id: string
  fullName: string
  email: string
  role: string
  lowestRole?: string
  scope?: string
  isActive: boolean
  twoFaEnabled: boolean
  lastLogin: string | null
  createdAt: string
}

// ── Activity types ────────────────────────────────────────────────────────────

export interface Activity {
  id: string
  activityType: number
  description: string
  primaryDescription: string | null
  agentId: string | null
  agentComputerName: string | null
  createdAt: string
  data: Record<string, unknown>
}

// ── Exclusion types ───────────────────────────────────────────────────────────

export interface Exclusion {
  id: string
  value: string
  type: string
  osType: string
  mode: string
  createdAt: string
}

// ── Firewall types ────────────────────────────────────────────────────────────

export interface FirewallRule {
  id: string
  name: string
  description: string | null
  action: string          // Allow | Block
  direction: string       // any | inbound | outbound
  protocol: string | null
  status: string          // Enabled | Disabled
  osType: string
  osTypes: string[]
  order: number
  scope: string
  scopeId: string | null
  editable: boolean
  ruleCategory: string
  creator: string | null
  creatorId: string | null
  localPort: { type: string; values: unknown[] }
  remotePort: { type: string; values: unknown[] }
  localHost: { type: string; values: unknown[] }
  remoteHost: { type: string; values: unknown[] }
  remoteHosts: { type: string; values: unknown[] }[]
  application: { type: string; values: unknown[] }
  location: { type: string; values: unknown[] }
  tagIds: string[]
  tagNames: string[]
  tags: { id: string; name: string }[]
  createdAt: string
  updatedAt: string
}

// ── Blocklist types ───────────────────────────────────────────────────────────

export interface BlocklistEntry {
  id: string
  value: string
  type: string
  description: string | null
  osType: string | null
  createdAt: string
}

// ── Device control types ──────────────────────────────────────────────────────

export interface DeviceControlRule {
  id: string
  ruleName: string
  action: string              // Allow | Block
  status: string              // Enabled | Disabled
  deviceClass: string
  deviceClassName: string
  interface: string           // USB | Bluetooth | Thunderbolt | SDCard
  ruleType: string
  order: number
  editable: boolean
  scope: string | null
  scopeName: string | null
  scopeId: string | null
  creator: string | null
  creatorId: string | null
  version: string | null
  vendorId: string | null
  productId: string | null
  deviceId: string | null
  uid: string | null
  accessPermission: string | null
  bluetoothAddress: string | null
  manufacturerName: string | null
  deviceName: string | null
  minorClasses: string[]
  gattService: string | null
  deviceInformationServiceInfoKey: string | null
  deviceInformationServiceInfoValue: string | null
  createdAt: string
  updatedAt: string
}

// ── Deep Visibility types ─────────────────────────────────────────────────────

export interface DvEvent {
  eventType: string
  eventTime: string
  agentName: string | null
  processName: string | null
  user: string | null
  details: string | null
}

// ── Auth types ────────────────────────────────────────────────────────────────

export interface PresetToken {
  label: string
  token: string
  role: string
}

// ── System types ──────────────────────────────────────────────────────────────

export type SystemStats = Record<string, number>

// ── Policy types ──────────────────────────────────────────────────────────────

export interface Policy {
  mitigationMode: string
  mitigationModeSuspicious: string
  autoMitigate: boolean
  scanNewAgents: boolean
  scanOnWritten: boolean
  monitorOnWrite: boolean
  monitorOnExecute: boolean
  blockOnWrite: boolean
  blockOnExecute: boolean
  engines: Record<string, boolean> | null
}

// ── Application / Process types ───────────────────────────────────────────────

export interface InstalledApp {
  id: string
  name: string
  version: string
  vendor: string
}

export interface AgentProcess {
  pid: number
  name: string
  cpuUsage: number
}

// ── Request Audit Log ─────────────────────────────────────────────────────────

export interface RequestLog {
  id: string
  timestamp: string
  method: string
  path: string
  query_string: string
  status_code: number
  duration_ms: number
  token_hint: string
}

// ── Webhook types ─────────────────────────────────────────────────────────────

export interface WebhookSubscription {
  id: string
  url: string
  event_types: string[]
  secret: string
  active: boolean
  description: string
  created_at: string
  updated_at: string
}

// ── Rate-limit config ─────────────────────────────────────────────────────────

export interface RateLimitConfig {
  enabled: boolean
  requests_per_minute: number
  active_counters: number
}

// ── Recording Proxy ───────────────────────────────────────────────────────────

export interface ProxyRecording {
  id: string
  method: string
  path: string
  query_string: string
  response_status: number
  response_content_type: string
  recorded_at: string
  base_url: string
}

export interface ProxyConfig {
  mode: 'off' | 'record' | 'replay'
  base_url: string
  api_token: string
  recording_count: number
}


// ── Tag definition types ──────────────────────────────────────────────────────

/** Scoped tag definition as returned by GET /agents/tags. */
export interface TagDefinition {
  id: string
  key: string
  value: string
  type: string
  description: string | null
  scopeId: string
  scopeLevel: 'global' | 'account' | 'site' | 'group'
  scopePath: string
  createdAt: string
  updatedAt: string
  createdBy: string
  updatedBy: string
  createdById: string
  updatedById: string
  allowEdit: boolean
  endpointsInCurrentScope: number
  totalEndpoints: number
  totalExclusions: number
}

// ── IOC types ─────────────────────────────────────────────────────────────────

export interface Ioc {
  uuid: string
  type: string
  value: string
  name: string | null
  description: string | null
  source: string
  externalId: string | null
  creationTime: string
  updatedAt: string
  validUntil: string | null
  category: string | null
  severity: string | null
}
