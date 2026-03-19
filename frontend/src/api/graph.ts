import axios from 'axios'
import type {
  ODataResponse,
  GraphTokenResponse,
  GraphUser,
  GraphGroup,
  GraphManagedDevice,
  GraphSecurityAlert,
  GraphSecurityIncident,
  GraphSecureScore,
  GraphConditionalAccessPolicy,
  GraphRiskyUser,
  GraphSignInLog,
  GraphAuditLog,
  GraphCompliancePolicy,
  GraphDeviceConfiguration,
  GraphAutopilotDevice,
  GraphMobileApp,
  GraphMailMessage,
  GraphMailFolder,
  GraphDrive,
  GraphDriveItem,
  GraphSharePointSite,
  GraphTeam,
  GraphChannel,
  GraphChatMessage,
  GraphSubscribedSku,
  GraphServiceHealth,
  GraphAttackSimulation,
} from '../types/graph'

/**
 * Axios instance for Microsoft Graph mock API.
 *
 * Uses Bearer token auth (stored as `graph_token` in localStorage) and the `/graph` prefix.
 * Response interceptor unwraps the Axios envelope so callers receive raw Graph response body.
 */
export const graphClient = axios.create({
  baseURL: '/graph',
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
})

graphClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('graph_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

graphClient.interceptors.response.use(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (response): any => response.data,
  (error: unknown) => {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      localStorage.removeItem('graph_token')
    }
    return Promise.reject(error)
  },
)

// ── Helper: auto-authenticate if no token ────────────────────────────────────

/** Fetch a Bearer token using OAuth2 client credentials and store in localStorage. */
export async function ensureGraphAuth(): Promise<void> {
  const existingToken = localStorage.getItem('graph_token')
  const expiresAt = localStorage.getItem('graph_token_expires_at')
  if (existingToken && expiresAt && Date.now() < Number(expiresAt) - 60000) return

  const form = new URLSearchParams()
  form.append('client_id', 'graph-mock-admin-client')
  form.append('client_secret', 'graph-mock-admin-secret')
  form.append('grant_type', 'client_credentials')

  const res = await axios.post<GraphTokenResponse>('/graph/oauth2/v2.0/token', form, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })

  localStorage.setItem('graph_token', res.data.access_token)
  localStorage.setItem('graph_token_expires_at', String(Date.now() + res.data.expires_in * 1000))
}

// ── Users API ───────────────────────────────────────────────────────────────

export const graphUsersApi = {
  /** List users. */
  list: (params?: Record<string, unknown>): Promise<ODataResponse<GraphUser>> =>
    graphClient.get('/v1.0/users', { params }) as Promise<ODataResponse<GraphUser>>,

  /** Get a single user by ID or UPN. */
  get: (id: string): Promise<GraphUser> =>
    graphClient.get(`/v1.0/users/${id}`) as Promise<GraphUser>,
}

// ── Groups API ──────────────────────────────────────────────────────────────

export const graphGroupsApi = {
  /** List groups. */
  list: (params?: Record<string, unknown>): Promise<ODataResponse<GraphGroup>> =>
    graphClient.get('/v1.0/groups', { params }) as Promise<ODataResponse<GraphGroup>>,

  /** Get a single group by ID. */
  get: (id: string): Promise<GraphGroup> =>
    graphClient.get(`/v1.0/groups/${id}`) as Promise<GraphGroup>,

  /** Get members of a group. */
  getMembers: (id: string): Promise<ODataResponse<GraphUser>> =>
    graphClient.get(`/v1.0/groups/${id}/members`) as Promise<ODataResponse<GraphUser>>,
}

// ── Devices API ─────────────────────────────────────────────────────────────

export const graphDevicesApi = {
  /** List managed devices. */
  list: (params?: Record<string, unknown>): Promise<ODataResponse<GraphManagedDevice>> =>
    graphClient.get('/v1.0/deviceManagement/managedDevices', { params }) as Promise<ODataResponse<GraphManagedDevice>>,

  /** Get a single managed device by ID. */
  get: (id: string): Promise<GraphManagedDevice> =>
    graphClient.get(`/v1.0/deviceManagement/managedDevices/${id}`) as Promise<GraphManagedDevice>,

  /** Wipe a managed device. */
  wipe: (id: string): Promise<unknown> =>
    graphClient.post(`/v1.0/deviceManagement/managedDevices/${id}/wipe`),

  /** Sync a managed device. */
  sync: (id: string): Promise<unknown> =>
    graphClient.post(`/v1.0/deviceManagement/managedDevices/${id}/syncDevice`),

  /** Trigger a Windows Defender scan on a managed device. */
  scan: (id: string, quickScan = true): Promise<unknown> =>
    graphClient.post(`/v1.0/deviceManagement/managedDevices/${id}/windowsDefenderScan`, { quickScan }),
}

// ── Security API ────────────────────────────────────────────────────────────

export const graphSecurityApi = {
  /** List security alerts (v2). */
  listAlerts: (params?: Record<string, unknown>): Promise<ODataResponse<GraphSecurityAlert>> =>
    graphClient.get('/v1.0/security/alerts_v2', { params }) as Promise<ODataResponse<GraphSecurityAlert>>,

  /** List security incidents. */
  listIncidents: (params?: Record<string, unknown>): Promise<ODataResponse<GraphSecurityIncident>> =>
    graphClient.get('/v1.0/security/incidents', { params }) as Promise<ODataResponse<GraphSecurityIncident>>,

  /** List secure scores. */
  listScores: (params?: Record<string, unknown>): Promise<ODataResponse<GraphSecureScore>> =>
    graphClient.get('/v1.0/security/secureScores', { params }) as Promise<ODataResponse<GraphSecureScore>>,
}

// ── Identity API ────────────────────────────────────────────────────────────

export const graphIdentityApi = {
  /** List conditional access policies. */
  listCaPolicies: (params?: Record<string, unknown>): Promise<ODataResponse<GraphConditionalAccessPolicy>> =>
    graphClient.get('/v1.0/identity/conditionalAccess/policies', { params }) as Promise<ODataResponse<GraphConditionalAccessPolicy>>,

  /** List risky users. */
  listRiskyUsers: (params?: Record<string, unknown>): Promise<ODataResponse<GraphRiskyUser>> =>
    graphClient.get('/v1.0/identityProtection/riskyUsers', { params }) as Promise<ODataResponse<GraphRiskyUser>>,

  /** List sign-in logs. */
  listSignInLogs: (params?: Record<string, unknown>): Promise<ODataResponse<GraphSignInLog>> =>
    graphClient.get('/v1.0/auditLogs/signIns', { params }) as Promise<ODataResponse<GraphSignInLog>>,

  /** List audit logs. */
  listAuditLogs: (params?: Record<string, unknown>): Promise<ODataResponse<GraphAuditLog>> =>
    graphClient.get('/v1.0/auditLogs/directoryAudits', { params }) as Promise<ODataResponse<GraphAuditLog>>,
}

// ── Intune API ──────────────────────────────────────────────────────────────

export const graphIntuneApi = {
  /** List device compliance policies. */
  listCompliance: (params?: Record<string, unknown>): Promise<ODataResponse<GraphCompliancePolicy>> =>
    graphClient.get('/v1.0/deviceManagement/deviceCompliancePolicies', { params }) as Promise<ODataResponse<GraphCompliancePolicy>>,

  /** List device configurations. */
  listConfigs: (params?: Record<string, unknown>): Promise<ODataResponse<GraphDeviceConfiguration>> =>
    graphClient.get('/v1.0/deviceManagement/deviceConfigurations', { params }) as Promise<ODataResponse<GraphDeviceConfiguration>>,

  /** List Autopilot devices. */
  listAutopilot: (params?: Record<string, unknown>): Promise<ODataResponse<GraphAutopilotDevice>> =>
    graphClient.get('/v1.0/deviceManagement/windowsAutopilotDeviceIdentities', { params }) as Promise<ODataResponse<GraphAutopilotDevice>>,

  /** List mobile apps. */
  listApps: (params?: Record<string, unknown>): Promise<ODataResponse<GraphMobileApp>> =>
    graphClient.get('/v1.0/deviceAppManagement/mobileApps', { params }) as Promise<ODataResponse<GraphMobileApp>>,
}

// ── Mail API ────────────────────────────────────────────────────────────────

export const graphMailApi = {
  /** List messages for a user (defaults to 'me'). */
  listMessages: (userId = 'me', params?: Record<string, unknown>): Promise<ODataResponse<GraphMailMessage>> =>
    graphClient.get(`/v1.0/${userId}/messages`, { params }) as Promise<ODataResponse<GraphMailMessage>>,

  /** List mail folders for a user (defaults to 'me'). */
  listFolders: (userId = 'me', params?: Record<string, unknown>): Promise<ODataResponse<GraphMailFolder>> =>
    graphClient.get(`/v1.0/${userId}/mailFolders`, { params }) as Promise<ODataResponse<GraphMailFolder>>,
}

// ── Files API ───────────────────────────────────────────────────────────────

export const graphFilesApi = {
  /** Get the default drive for a user (defaults to 'me'). */
  getDrive: (userId = 'me'): Promise<GraphDrive> =>
    graphClient.get(`/v1.0/${userId}/drive`) as Promise<GraphDrive>,

  /** List children in the root of a drive. */
  listChildren: (userId = 'me', itemId = 'root', params?: Record<string, unknown>): Promise<ODataResponse<GraphDriveItem>> =>
    graphClient.get(`/v1.0/${userId}/drive/items/${itemId}/children`, { params }) as Promise<ODataResponse<GraphDriveItem>>,

  /** List SharePoint sites. */
  listSites: (params?: Record<string, unknown>): Promise<ODataResponse<GraphSharePointSite>> =>
    graphClient.get('/v1.0/sites', { params }) as Promise<ODataResponse<GraphSharePointSite>>,
}

// ── Teams API ───────────────────────────────────────────────────────────────

export const graphTeamsApi = {
  /** List joined teams. */
  list: (params?: Record<string, unknown>): Promise<ODataResponse<GraphTeam>> =>
    graphClient.get('/v1.0/teams', { params }) as Promise<ODataResponse<GraphTeam>>,

  /** Get channels for a team. */
  getChannels: (teamId: string): Promise<ODataResponse<GraphChannel>> =>
    graphClient.get(`/v1.0/teams/${teamId}/channels`) as Promise<ODataResponse<GraphChannel>>,

  /** Get messages in a channel. */
  getMessages: (teamId: string, channelId: string, params?: Record<string, unknown>): Promise<ODataResponse<GraphChatMessage>> =>
    graphClient.get(`/v1.0/teams/${teamId}/channels/${channelId}/messages`, { params }) as Promise<ODataResponse<GraphChatMessage>>,
}

// ── Admin API ───────────────────────────────────────────────────────────────

export const graphAdminApi = {
  /** List subscribed SKUs (license info). */
  listSkus: (params?: Record<string, unknown>): Promise<ODataResponse<GraphSubscribedSku>> =>
    graphClient.get('/v1.0/subscribedSkus', { params }) as Promise<ODataResponse<GraphSubscribedSku>>,

  /** List service health statuses. */
  listServiceHealth: (params?: Record<string, unknown>): Promise<ODataResponse<GraphServiceHealth>> =>
    graphClient.get('/v1.0/admin/serviceAnnouncement/healthOverviews', { params }) as Promise<ODataResponse<GraphServiceHealth>>,

  /** List attack simulation campaigns. */
  listSimulations: (params?: Record<string, unknown>): Promise<ODataResponse<GraphAttackSimulation>> =>
    graphClient.get('/v1.0/security/attackSimulation/simulations', { params }) as Promise<ODataResponse<GraphAttackSimulation>>,
}
