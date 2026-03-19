// ── OData response wrapper ──────────────────────────────────────────────────

/** Standard Microsoft Graph OData collection response envelope. */
export interface ODataResponse<T> {
  '@odata.context'?: string
  '@odata.count'?: number
  '@odata.nextLink'?: string
  value: T[]
}

// ── Auth ────────────────────────────────────────────────────────────────────

export interface GraphTokenResponse {
  access_token: string
  token_type: string
  expires_in: number
}

// ── Users ───────────────────────────────────────────────────────────────────

export interface GraphUser {
  id: string
  userPrincipalName: string
  displayName: string
  mail: string | null
  jobTitle: string | null
  department: string | null
  accountEnabled: boolean
  createdDateTime: string
  signInActivity?: { lastSignInDateTime: string }
  assignedLicenses?: Array<{ skuId: string }>
}

// ── Groups ──────────────────────────────────────────────────────────────────

export interface GraphGroup {
  id: string
  displayName: string
  description: string
  groupTypes: string[]
  securityEnabled: boolean
  membershipRule?: string | null
  createdDateTime: string
}

// ── Devices ─────────────────────────────────────────────────────────────────

export interface GraphManagedDevice {
  id: string
  deviceName: string
  operatingSystem: string
  osVersion: string
  lastSyncDateTime: string
  complianceState: string
  managementState: string
  userPrincipalName: string
  model: string
  manufacturer: string
}

// ── Security ────────────────────────────────────────────────────────────────

export interface GraphSecurityAlert {
  id: string
  title: string
  severity: string
  status: string
  category: string
  createdDateTime: string
  serviceSource: string
  assignedTo: string | null
}

export interface GraphSecurityIncident {
  id: string
  displayName: string
  severity: string
  status: string
  createdDateTime: string
  assignedTo: string | null
  alert_ids?: string[]
}

// ── Conditional Access Policies ─────────────────────────────────────────────

export interface GraphConditionalAccessPolicy {
  id: string
  displayName: string
  state: string
  conditions: Record<string, unknown>
  grantControls: Record<string, unknown>
}

// ── Directory Roles ─────────────────────────────────────────────────────────

export interface GraphDirectoryRole {
  id: string
  displayName: string
  description: string
  roleTemplateId: string
}

// ── Service Principals ──────────────────────────────────────────────────────

export interface GraphServicePrincipal {
  id: string
  appId: string
  displayName: string
  servicePrincipalType: string
  accountEnabled: boolean
}

// ── Subscribed SKUs (Licenses) ──────────────────────────────────────────────

export interface GraphSubscribedSku {
  id: string
  skuId: string
  skuPartNumber: string
  capabilityStatus: string
  consumedUnits: number
  prepaidUnits: {
    enabled: number
    suspended: number
    warning: number
  }
}

// ── Sign-In Logs ────────────────────────────────────────────────────────────

export interface GraphSignInLog {
  id: string
  userPrincipalName: string
  userDisplayName: string
  appDisplayName: string
  ipAddress: string
  clientAppUsed: string
  status: { errorCode: number; failureReason: string | null }
  createdDateTime: string
  location: { city: string | null; state: string | null; countryOrRegion: string | null }
}

// ── Audit Logs ──────────────────────────────────────────────────────────────

export interface GraphAuditLog {
  id: string
  activityDisplayName: string
  activityDateTime: string
  category: string
  result: string
  initiatedBy: Record<string, unknown>
  targetResources: Array<Record<string, unknown>>
}

// ── Risky Users ─────────────────────────────────────────────────────────────

export interface GraphRiskyUser {
  id: string
  userPrincipalName: string
  userDisplayName: string
  riskLevel: string
  riskState: string
  riskDetail: string
  riskLastUpdatedDateTime: string
}

// ── Secure Score ────────────────────────────────────────────────────────────

export interface GraphSecureScore {
  id: string
  currentScore: number
  maxScore: number
  createdDateTime: string
  controlScores: Array<{
    controlName: string
    score: number
    description: string
  }>
}

// ── Compliance Policy ───────────────────────────────────────────────────────

export interface GraphCompliancePolicy {
  id: string
  displayName: string
  description: string | null
  lastModifiedDateTime: string
  createdDateTime: string
}

// ── Autopilot Devices ───────────────────────────────────────────────────────

export interface GraphAutopilotDevice {
  id: string
  serialNumber: string
  model: string
  manufacturer: string
  groupTag: string | null
  enrollmentState: string
  lastContactedDateTime: string
}

// ── Mobile Apps ─────────────────────────────────────────────────────────────

export interface GraphMobileApp {
  id: string
  displayName: string
  description: string | null
  publisher: string
  publishingState: string
  installSummary?: { installedDeviceCount: number; failedDeviceCount: number }
}

// ── Teams ───────────────────────────────────────────────────────────────────

export interface GraphTeam {
  id: string
  displayName: string
  description: string | null
  visibility: string
  createdDateTime: string
}

export interface GraphChannel {
  id: string
  displayName: string
  description: string | null
  membershipType: string
}

export interface GraphChatMessage {
  id: string
  body: { content: string; contentType: string }
  from: { user: { displayName: string; id: string } } | null
  createdDateTime: string
}

// ── Mail ────────────────────────────────────────────────────────────────────

export interface GraphMailMessage {
  id: string
  subject: string
  bodyPreview: string
  from: { emailAddress: { name: string; address: string } } | null
  receivedDateTime: string
  isRead: boolean
  hasAttachments: boolean
}

export interface GraphMailFolder {
  id: string
  displayName: string
  totalItemCount: number
  unreadItemCount: number
}

// ── OneDrive / Files ────────────────────────────────────────────────────────

export interface GraphDriveItem {
  id: string
  name: string
  size: number
  createdDateTime: string
  lastModifiedDateTime: string
  webUrl: string
  folder?: { childCount: number }
  file?: { mimeType: string }
}

export interface GraphDrive {
  id: string
  name: string
  driveType: string
  owner: { user?: { displayName: string } }
  quota: { total: number; used: number; remaining: number }
}

// ── SharePoint Sites ────────────────────────────────────────────────────────

export interface GraphSharePointSite {
  id: string
  displayName: string
  name: string
  webUrl: string
  createdDateTime: string
}

// ── Service Health ──────────────────────────────────────────────────────────

export interface GraphServiceHealth {
  id: string
  service: string
  status: string
  isActive: boolean
}

// ── Attack Simulation ───────────────────────────────────────────────────────

export interface GraphAttackSimulation {
  id: string
  displayName: string
  status: string
  attackType: string
  launchDateTime: string
  completionDateTime: string | null
  report?: {
    compromisedRate: number
    reportedRate: number
  }
}

// ── Device Configuration ────────────────────────────────────────────────────

export interface GraphDeviceConfiguration {
  id: string
  displayName: string
  description: string | null
  lastModifiedDateTime: string
  createdDateTime: string
}
