import axios from 'axios'
import type {
  XdrResponse,
  XdrIncident,
  XdrAlert,
  XdrEndpoint,
  XdrIncidentExtraData,
  XdrHashException,
  XdrScript,
} from '../types/cortex'

const XDR_KEY_ID = import.meta.env.VITE_XDR_KEY_ID
const XDR_SECRET = import.meta.env.VITE_XDR_KEY_SECRET

/** Generate a random 64-char hex string. */
function randomNonce(): string {
  const arr = new Uint8Array(32)
  crypto.getRandomValues(arr)
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('')
}

/** Compute HMAC-SHA256 hex digest using Web Crypto API. */
async function hmacSha256Hex(key: string, message: string): Promise<string> {
  const enc = new TextEncoder()
  const cryptoKey = await crypto.subtle.importKey(
    'raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  )
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(message))
  return Array.from(new Uint8Array(sig), b => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Axios instance for Cortex XDR mock API.
 *
 * Uses HMAC auth with x-xdr-auth-id, x-xdr-nonce, x-xdr-timestamp, and Authorization headers.
 * All requests are POST with { request_data: { ... } } body shape.
 * Response interceptor unwraps the Axios envelope so callers receive raw XDR response body.
 */
const xdrClient = axios.create({
  baseURL: '/xdr/public_api/v1',
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
})

xdrClient.interceptors.request.use(async (config) => {
  const nonce = randomNonce()
  const timestamp = Date.now().toString()
  const authHash = await hmacSha256Hex(XDR_SECRET, nonce + ':' + timestamp)

  config.headers['x-xdr-auth-id'] = XDR_KEY_ID
  config.headers['x-xdr-nonce'] = nonce
  config.headers['x-xdr-timestamp'] = timestamp
  config.headers['Authorization'] = authHash
  return config
})

xdrClient.interceptors.response.use(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (response): any => response.data,
  (error) => {
    return Promise.reject(error)
  },
)

// ── Incidents API ──────────────────────────────────────────────────────────

export const xdrIncidentsApi = {
  /** Get incidents list. */
  list: (filters?: Record<string, unknown>): Promise<XdrResponse<{ total_count: number; result_count: number; incidents: XdrIncident[] }>> =>
    xdrClient.post('/incidents/get_incidents/', {
      request_data: { filters: filters ? [filters] : [], sort: { field: 'creation_time', keyword: 'desc' } },
    }) as Promise<XdrResponse<{ total_count: number; result_count: number; incidents: XdrIncident[] }>>,

  /** Get incident extra data (detail). */
  getExtraData: (incidentId: string): Promise<XdrResponse<XdrIncidentExtraData>> =>
    xdrClient.post('/incidents/get_incident_extra_data/', {
      request_data: { incident_id: incidentId },
    }) as Promise<XdrResponse<XdrIncidentExtraData>>,

  /** Update incident (status, assign, etc). */
  update: (incidentId: string, data: Record<string, unknown>): Promise<unknown> =>
    xdrClient.post('/incidents/update_incident/', {
      request_data: { incident_id: incidentId, update_data: data },
    }),
}

// ── Alerts API ─────────────────────────────────────────────────────────────

export const xdrAlertsApi = {
  /** Get alerts by filter. */
  list: (filters?: Record<string, unknown>[]): Promise<XdrResponse<{ total_count: number; result_count: number; alerts: XdrAlert[] }>> =>
    xdrClient.post('/alerts/get_alerts_by_filter_data/', {
      request_data: { filters: filters ?? [], sort: { field: 'detection_timestamp', keyword: 'desc' } },
    }) as Promise<XdrResponse<{ total_count: number; result_count: number; alerts: XdrAlert[] }>>,
}

// ── Endpoints API ──────────────────────────────────────────────────────────

export const xdrEndpointsApi = {
  /** Get all endpoints. */
  list: (filters?: Record<string, unknown>[]): Promise<XdrResponse<{ total_count: number; result_count: number; endpoints: XdrEndpoint[] }>> =>
    xdrClient.post('/endpoints/get_endpoint/', {
      request_data: { filters: filters ?? [] },
    }) as Promise<XdrResponse<{ total_count: number; result_count: number; endpoints: XdrEndpoint[] }>>,

  /** Isolate endpoints. */
  isolate: (endpointId: string): Promise<unknown> =>
    xdrClient.post('/endpoints/isolate/', {
      request_data: { endpoint_id: endpointId },
    }),

  /** Unisolate endpoints. */
  unisolate: (endpointId: string): Promise<unknown> =>
    xdrClient.post('/endpoints/unisolate/', {
      request_data: { endpoint_id: endpointId },
    }),

  /** Scan endpoint. */
  scan: (endpointId: string): Promise<unknown> =>
    xdrClient.post('/endpoints/scan/', {
      request_data: { endpoint_id: endpointId },
    }),
}

// ── Hash Exceptions API ───────────────────────────────────────────────────

export const xdrHashExceptionsApi = {
  /** Get blocklist entries. */
  getBlocklist: (): Promise<XdrResponse<{ total_count: number; result_count: number; data: XdrHashException[] }>> =>
    xdrClient.post('/hash_exceptions/blocklist/get/', {
      request_data: {},
    }) as Promise<XdrResponse<{ total_count: number; result_count: number; data: XdrHashException[] }>>,

  /** Get allowlist entries. */
  getAllowlist: (): Promise<XdrResponse<{ total_count: number; result_count: number; data: XdrHashException[] }>> =>
    xdrClient.post('/hash_exceptions/allowlist/get/', {
      request_data: {},
    }) as Promise<XdrResponse<{ total_count: number; result_count: number; data: XdrHashException[] }>>,

  /** Add hashes to blocklist. */
  addToBlocklist: (hashes: { hash: string; comment?: string }[]): Promise<unknown> =>
    xdrClient.post('/hash_exceptions/blocklist/', {
      request_data: { hash_list: hashes },
    }),

  /** Remove hashes from blocklist. */
  removeFromBlocklist: (hashes: string[]): Promise<unknown> =>
    xdrClient.post('/hash_exceptions/blocklist/remove/', {
      request_data: { hash_list: hashes },
    }),

  /** Add hashes to allowlist. */
  addToAllowlist: (hashes: { hash: string; comment?: string }[]): Promise<unknown> =>
    xdrClient.post('/hash_exceptions/allowlist/', {
      request_data: { hash_list: hashes },
    }),

  /** Remove hashes from allowlist. */
  removeFromAllowlist: (hashes: string[]): Promise<unknown> =>
    xdrClient.post('/hash_exceptions/allowlist/remove/', {
      request_data: { hash_list: hashes },
    }),
}

// ── Scripts API ───────────────────────────────────────────────────────────

export const xdrScriptsApi = {
  /** Get all scripts. */
  list: (): Promise<XdrResponse<{ total_count: number; result_count: number; scripts: XdrScript[] }>> =>
    xdrClient.post('/scripts/get_scripts/', {
      request_data: {},
    }) as Promise<XdrResponse<{ total_count: number; result_count: number; scripts: XdrScript[] }>>,
}
