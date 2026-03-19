import axios from 'axios'
import type {
  MdeODataResponse,
  MdeMachine,
  MdeAlert,
  MdeIndicator,
  MdeSoftware,
  MdeVulnerability,
} from '../types/defender'

/**
 * Axios instance for Microsoft Defender for Endpoint mock API.
 *
 * Uses Bearer token auth (stored as `mde_token` in localStorage) and the `/mde` prefix.
 * Response interceptor unwraps the Axios envelope so callers receive raw MDE response body.
 */
const mdeClient = axios.create({
  baseURL: '/mde',
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
})

mdeClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('mde_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

mdeClient.interceptors.response.use(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (response): any => response.data,
  (error: unknown) => {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      localStorage.removeItem('mde_token')
    }
    return Promise.reject(error)
  },
)

// ── Helper: auto-authenticate if no token ────────────────────────────────────

const MDE_CLIENT_ID = import.meta.env.VITE_MDE_CLIENT_ID
const MDE_CLIENT_SECRET = import.meta.env.VITE_MDE_CLIENT_SECRET

interface MdeTokenResponse {
  access_token: string
  token_type: string
  expires_in: number
}

/** Fetch a Bearer token using OAuth2 client credentials and store in localStorage. */
export async function ensureMdeAuth(): Promise<void> {
  const existingToken = localStorage.getItem('mde_token')
  const expiresAt = localStorage.getItem('mde_token_expires_at')
  if (existingToken && expiresAt && Date.now() < Number(expiresAt) - 60000) return
  const form = new URLSearchParams()
  form.append('client_id', MDE_CLIENT_ID)
  form.append('client_secret', MDE_CLIENT_SECRET)
  form.append('grant_type', 'client_credentials')
  const res = await axios.post<MdeTokenResponse>('/mde/oauth2/v2.0/token', form, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  localStorage.setItem('mde_token', res.data.access_token)
  localStorage.setItem('mde_token_expires_at', String(Date.now() + res.data.expires_in * 1000))
}

// ── Machines API ─────────────────────────────────────────────────────────────

export const mdeMachinesApi = {
  /** List machines with OData query params. */
  list: (params?: Record<string, unknown>): Promise<MdeODataResponse<MdeMachine>> =>
    mdeClient.get('/api/machines', { params }) as Promise<MdeODataResponse<MdeMachine>>,

  /** Get a single machine by ID. */
  get: (id: string): Promise<MdeMachine> =>
    mdeClient.get(`/api/machines/${id}`) as Promise<MdeMachine>,

  /** Isolate a machine. */
  isolate: (id: string, comment: string): Promise<unknown> =>
    mdeClient.post(`/api/machines/${id}/isolate`, { Comment: comment, IsolationType: 'Full' }),

  /** Release from isolation. */
  unisolate: (id: string, comment: string): Promise<unknown> =>
    mdeClient.post(`/api/machines/${id}/unisolate`, { Comment: comment }),

  /** Run antivirus scan. */
  scanAction: (id: string, scanType: string): Promise<unknown> =>
    mdeClient.post(`/api/machines/${id}/runAntiVirusScan`, { Comment: 'Scan initiated', ScanType: scanType }),
}

// ── Alerts API ──────────────────────────────────────────────────────────────

export const mdeAlertsApi = {
  /** List alerts with OData query params. */
  list: (params?: Record<string, unknown>): Promise<MdeODataResponse<MdeAlert>> =>
    mdeClient.get('/api/alerts', { params }) as Promise<MdeODataResponse<MdeAlert>>,

  /** Get a single alert by ID. */
  get: (id: string): Promise<MdeAlert> =>
    mdeClient.get(`/api/alerts/${id}`) as Promise<MdeAlert>,

  /** Update alert (PATCH). */
  update: (id: string, body: Record<string, unknown>): Promise<MdeAlert> =>
    mdeClient.patch(`/api/alerts/${id}`, body) as Promise<MdeAlert>,
}

// ── Indicators API ──────────────────────────────────────────────────────────

export const mdeIndicatorsApi = {
  /** List indicators. */
  list: (params?: Record<string, unknown>): Promise<MdeODataResponse<MdeIndicator>> =>
    mdeClient.get('/api/indicators', { params }) as Promise<MdeODataResponse<MdeIndicator>>,

  /** Get a single indicator by ID. */
  get: (id: string): Promise<MdeIndicator> =>
    mdeClient.get(`/api/indicators/${id}`) as Promise<MdeIndicator>,

  /** Create an indicator. */
  create: (body: Partial<MdeIndicator>): Promise<MdeIndicator> =>
    mdeClient.post('/api/indicators', body) as Promise<MdeIndicator>,

  /** Update an indicator. */
  update: (id: string, body: Partial<MdeIndicator>): Promise<MdeIndicator> =>
    mdeClient.patch(`/api/indicators/${id}`, body) as Promise<MdeIndicator>,

  /** Delete an indicator. */
  delete: (id: string): Promise<unknown> =>
    mdeClient.delete(`/api/indicators/${id}`),
}

// ── Software API ────────────────────────────────────────────────────────────

export const mdeSoftwareApi = {
  /** List software inventory. */
  list: (params?: Record<string, unknown>): Promise<MdeODataResponse<MdeSoftware>> =>
    mdeClient.get('/api/software', { params }) as Promise<MdeODataResponse<MdeSoftware>>,

  /** Get a single software entry. */
  get: (id: string): Promise<MdeSoftware> =>
    mdeClient.get(`/api/software/${id}`) as Promise<MdeSoftware>,
}

// ── Vulnerabilities API ─────────────────────────────────────────────────────

export const mdeVulnerabilitiesApi = {
  /** List vulnerabilities. */
  list: (params?: Record<string, unknown>): Promise<MdeODataResponse<MdeVulnerability>> =>
    mdeClient.get('/api/vulnerabilities', { params }) as Promise<MdeODataResponse<MdeVulnerability>>,

  /** Get a single vulnerability. */
  get: (id: string): Promise<MdeVulnerability> =>
    mdeClient.get(`/api/vulnerabilities/${id}`) as Promise<MdeVulnerability>,
}
