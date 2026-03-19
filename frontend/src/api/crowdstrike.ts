import axios from 'axios'
import type {
  CsResponse,
  CsHost,
  CsDetection,
  CsIncident,
  CsIoc,
  CsHostGroup,
  CsCase,
} from '../types/crowdstrike'

/**
 * Separate Axios instance for CrowdStrike mock API.
 *
 * Uses Bearer token auth (stored as `cs_token` in localStorage) and the `/cs` prefix.
 * Response interceptor unwraps the Axios envelope so callers receive raw CS response body.
 */
const csClient = axios.create({
  baseURL: '/cs',
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
})

csClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('cs_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

csClient.interceptors.response.use(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (response): any => response.data,
  (error: unknown) => {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      localStorage.removeItem('cs_token')
    }
    return Promise.reject(error)
  },
)

// ── Helper: auto-authenticate if no token ────────────────────────────────────

const CS_CLIENT_ID = import.meta.env.VITE_CS_CLIENT_ID
const CS_CLIENT_SECRET = import.meta.env.VITE_CS_CLIENT_SECRET

interface TokenResponse {
  access_token: string
  token_type: string
  expires_in: number
}

/** Fetch a Bearer token using OAuth2 client credentials and store in localStorage. */
export async function ensureCsAuth(): Promise<void> {
  const existingToken = localStorage.getItem('cs_token')
  const expiresAt = localStorage.getItem('cs_token_expires_at')
  if (existingToken && expiresAt && Date.now() < Number(expiresAt) - 60000) return
  const form = new URLSearchParams()
  form.append('client_id', CS_CLIENT_ID)
  form.append('client_secret', CS_CLIENT_SECRET)
  const res = await axios.post<TokenResponse>('/cs/oauth2/token', form, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  localStorage.setItem('cs_token', res.data.access_token)
  localStorage.setItem('cs_token_expires_at', String(Date.now() + res.data.expires_in * 1000))
}

// ── Auth API ─────────────────────────────────────────────────────────────────

export const csAuthApi = {
  getToken: (clientId: string, clientSecret: string): Promise<TokenResponse> => {
    const form = new URLSearchParams()
    form.append('client_id', clientId)
    form.append('client_secret', clientSecret)
    return csClient.post('/oauth2/token', form, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    }) as Promise<TokenResponse>
  },
}

// ── Hosts API ────────────────────────────────────────────────────────────────

export const csHostsApi = {
  /** Query host device IDs. */
  queryIds: (params?: Record<string, unknown>): Promise<CsResponse<string>> =>
    csClient.get('/devices/queries/devices/v1', { params }) as Promise<CsResponse<string>>,

  /** Fetch full host entities by IDs. */
  getEntities: (ids: string[]): Promise<CsResponse<CsHost>> =>
    csClient.post('/devices/entities/devices/v2', { ids }) as Promise<CsResponse<CsHost>>,

  /** Perform a host action (contain, lift_containment, etc.). */
  action: (actionName: string, ids: string[]): Promise<CsResponse<CsHost>> =>
    csClient.post('/devices/entities/devices-actions/v2', { ids }, {
      params: { action_name: actionName },
    }) as Promise<CsResponse<CsHost>>,
}

// ── Detections API ───────────────────────────────────────────────────────────

export const csDetectionsApi = {
  /** Query detection/alert IDs. */
  queryIds: (params?: Record<string, unknown>): Promise<CsResponse<string>> =>
    csClient.get('/alerts/queries/alerts/v2', { params }) as Promise<CsResponse<string>>,

  /** Fetch full detection entities by IDs. */
  getEntities: (ids: string[]): Promise<CsResponse<CsDetection>> =>
    csClient.post('/alerts/entities/alerts/v2', { ids }) as Promise<CsResponse<CsDetection>>,

  /** Update detection status. */
  update: (ids: string[], updates: Record<string, unknown>): Promise<CsResponse<CsDetection>> =>
    csClient.patch('/alerts/entities/alerts/v3', { ids, ...updates }) as Promise<CsResponse<CsDetection>>,
}

// ── Incidents API ────────────────────────────────────────────────────────────

export const csIncidentsApi = {
  /** Query incident IDs. */
  queryIds: (params?: Record<string, unknown>): Promise<CsResponse<string>> =>
    csClient.get('/incidents/queries/incidents/v1', { params }) as Promise<CsResponse<string>>,

  /** Fetch full incident entities by IDs. */
  getEntities: (ids: string[]): Promise<CsResponse<CsIncident>> =>
    csClient.post('/incidents/entities/incidents/GET/v1', { ids }) as Promise<CsResponse<CsIncident>>,

  /** Perform incident actions (update status, assign, etc.). */
  action: (ids: string[], actionParams: Array<{ name: string; value: string }>): Promise<CsResponse<unknown>> =>
    csClient.post('/incidents/entities/incident-actions/v1', {
      ids,
      action_parameters: actionParams,
    }) as Promise<CsResponse<unknown>>,
}

// ── IOCs API ─────────────────────────────────────────────────────────────────

export const csIocsApi = {
  /** Combined search for IOC indicators. */
  search: (params?: Record<string, unknown>): Promise<CsResponse<CsIoc>> =>
    csClient.get('/iocs/combined/indicator/v1', { params }) as Promise<CsResponse<CsIoc>>,

  /** Create IOC indicators. */
  create: (indicators: Partial<CsIoc>[]): Promise<CsResponse<CsIoc>> =>
    csClient.post('/iocs/entities/indicators/v1', { indicators }) as Promise<CsResponse<CsIoc>>,

  /** Delete IOC indicators by IDs. */
  delete: (ids: string[]): Promise<CsResponse<unknown>> =>
    csClient.delete('/iocs/entities/indicators/v1', {
      params: { ids: ids.join(',') },
    }) as Promise<CsResponse<unknown>>,
}

// ── Host Groups API ──────────────────────────────────────────────────────────

export const csHostGroupsApi = {
  /** Combined list of host groups. */
  list: (params?: Record<string, unknown>): Promise<CsResponse<CsHostGroup>> =>
    csClient.get('/devices/combined/host-groups/v1', { params }) as Promise<CsResponse<CsHostGroup>>,
}

// ── Cases API ───────────────────────────────────────────────────────────────

export const csCasesApi = {
  /** List all cases. */
  list: (params?: Record<string, unknown>): Promise<CsResponse<CsCase>> =>
    csClient.get('/cases/entities/cases/GET/v1', { params }) as Promise<CsResponse<CsCase>>,
}
