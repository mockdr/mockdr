import axios from 'axios'
import { reportFailure } from './report'
import type {
  ArmResource,
  ArmList,
  SentinelIncidentProps,
  SentinelAlertProps,
  SentinelWatchlistProps,
  SentinelThreatIndicatorProps,
  SentinelAlertRuleProps,
} from '../types/sentinel'

const SENTINEL_CLIENT_ID = 'sentinel-mock-client-id'
const SENTINEL_CLIENT_SECRET = 'sentinel-mock-client-secret'

// ARM rejects any management-plane request without this, so every caller below
// has to send it — including the ones that bypass `sentinelClient`.
const API_VERSION = '2024-03-01'

let accessToken = ''

const sentinelClient = axios.create({
  baseURL: '/sentinel',
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
  params: { 'api-version': API_VERSION },
})

// Request interceptor: add Bearer token, auto-fetch if missing
sentinelClient.interceptors.request.use(async (config) => {
  if (!accessToken) {
    const tokenRes = await axios.post('/sentinel/oauth2/v2.0/token', new URLSearchParams({
      client_id: SENTINEL_CLIENT_ID,
      client_secret: SENTINEL_CLIENT_SECRET,
      grant_type: 'client_credentials',
      // Required by Entra; without it the token call is refused and every
      // Sentinel page answers with its empty state. See `graph.ts`.
      scope: 'https://management.azure.com/.default',
    }))
    accessToken = tokenRes.data.access_token
  }
  config.headers.Authorization = `Bearer ${accessToken}`
  return config
})

// Response interceptor: unwrap Axios envelope
sentinelClient.interceptors.response.use(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (r): any => r.data,
  (err) => {
    void reportFailure(err, 'Sentinel')
    if (err.response?.status === 401) accessToken = ''
    return Promise.reject(err)
  },
)

const WS_PREFIX = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/mockdr-rg/providers/Microsoft.OperationalInsights/workspaces/mockdr-workspace/providers/Microsoft.SecurityInsights'

export const sentinelIncidentApi = {
  list: (top = 50): Promise<ArmList<SentinelIncidentProps>> =>
    sentinelClient.get(`${WS_PREFIX}/incidents`, { params: { $top: top } }),
  get: (id: string): Promise<ArmResource<SentinelIncidentProps>> =>
    sentinelClient.get(`${WS_PREFIX}/incidents/${id}`),
  update: (id: string, props: Record<string, unknown>): Promise<ArmResource<SentinelIncidentProps>> =>
    sentinelClient.put(`${WS_PREFIX}/incidents/${id}`, { properties: props }),
  getAlerts: (id: string): Promise<ArmList<SentinelAlertProps>> =>
    sentinelClient.post(`${WS_PREFIX}/incidents/${id}/alerts`),
  getEntities: (id: string): Promise<{ entities: unknown[]; metaData: { count: number } }> =>
    sentinelClient.post(`${WS_PREFIX}/incidents/${id}/entities`),
  getComments: (id: string): Promise<ArmList> =>
    sentinelClient.get(`${WS_PREFIX}/incidents/${id}/comments`),
  addComment: (incId: string, commentId: string, message: string): Promise<unknown> =>
    sentinelClient.put(`${WS_PREFIX}/incidents/${incId}/comments/${commentId}`, { properties: { message } }),
}

export const sentinelWatchlistApi = {
  list: (): Promise<ArmList<SentinelWatchlistProps>> =>
    sentinelClient.get(`${WS_PREFIX}/watchlists`),
}

export const sentinelThreatIntelApi = {
  list: (top = 50): Promise<ArmList<SentinelThreatIndicatorProps>> =>
    sentinelClient.get(`${WS_PREFIX}/threatIntelligence/main/indicators`, { params: { $top: top } }),
}

export const sentinelAlertRuleApi = {
  list: (): Promise<ArmList<SentinelAlertRuleProps>> =>
    sentinelClient.get(`${WS_PREFIX}/alertRules`),
}

export const sentinelOperationsApi = {
  info: (): Promise<unknown> =>
    axios
      .get('/sentinel/providers/Microsoft.SecurityInsights/operations', {
        params: { 'api-version': API_VERSION },
      })
      .then(r => r.data),
}
