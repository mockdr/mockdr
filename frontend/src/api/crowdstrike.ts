import axios from 'axios'
import { reportFailure } from './report'
import type {
  CsResponse,
  CsHost,
  CsDetection,
  CsIoc,
  CsHostGroup,
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
    void reportFailure(error, 'CrowdStrike')
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

  /**
   * Fetch full alert entities by composite id.
   *
   * gofalcon marks `composite_ids` required on the v2 entities route and on
   * the v3 update; `ids` is the v1 and v2-PATCH spelling. This mock reads
   * either -- it will not invent a refusal whose wording nobody has
   * measured -- but Falcon requires the newer name on these two, so a
   * console sending the older one works here and 400s in production.
   */
  getEntities: (ids: string[]): Promise<CsResponse<CsDetection>> =>
    csClient.post('/alerts/entities/alerts/v2',
      { composite_ids: ids }) as Promise<CsResponse<CsDetection>>,

  /** Update alert status, under the names the v3 route requires. */
  update: (ids: string[], updates: Record<string, unknown>): Promise<CsResponse<CsDetection>> =>
    csClient.patch('/alerts/entities/alerts/v3',
      { composite_ids: ids, ...updates }) as Promise<CsResponse<CsDetection>>,
}

// ── Incidents API ────────────────────────────────────────────────────────────


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

