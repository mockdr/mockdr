import axios from 'axios'
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

let accessToken = ''

const sentinelClient = axios.create({
  baseURL: '/sentinel',
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
  params: { 'api-version': '2024-03-01' },
})

// Request interceptor: add Bearer token, auto-fetch if missing
sentinelClient.interceptors.request.use(async (config) => {
  if (!accessToken) {
    const tokenRes = await axios.post('/sentinel/oauth2/v2.0/token', new URLSearchParams({
      client_id: SENTINEL_CLIENT_ID,
      client_secret: SENTINEL_CLIENT_SECRET,
      grant_type: 'client_credentials',
    }))
    accessToken = tokenRes.data.access_token
  }
  config.headers.Authorization = `Bearer ${accessToken}`
  return config
})

// Response interceptor: unwrap Axios envelope
sentinelClient.interceptors.response.use(
  (r): any => r.data,
  (err) => {
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
    axios.get('/sentinel/providers/Microsoft.SecurityInsights/operations').then(r => r.data),
}
