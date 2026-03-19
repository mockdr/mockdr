import axios from 'axios'
import type {
  SplunkEnvelope,
  SplunkSearchResults,

  SplunkHecResponse,
  SplunkIndex,
  SplunkJobStatus,
  SplunkNotable,
  SplunkHecToken,
} from '../types/splunk'

const SPLUNK_USER = import.meta.env.VITE_SPLUNK_USERNAME
const SPLUNK_PASS = import.meta.env.VITE_SPLUNK_PASSWORD

/**
 * Axios instance for Splunk mock API.
 *
 * Uses Basic Auth (admin:mockdr-admin) for all management endpoints.
 * Response interceptor unwraps the Axios envelope.
 */
const splunkClient = axios.create({
  baseURL: '/splunk',
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Basic ' + btoa(`${SPLUNK_USER}:${SPLUNK_PASS}`),
  },
  params: { output_mode: 'json' },
})

splunkClient.interceptors.response.use(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (response): any => response.data,
  (error) => Promise.reject(error),
)

// ── Server Info ───────────────────────────────────────────────────────────

export const splunkServerApi = {
  /** Get server info. */
  info: (): Promise<SplunkEnvelope> =>
    splunkClient.get('/services/server/info') as Promise<SplunkEnvelope>,

  /** Get server status. */
  status: (): Promise<SplunkEnvelope> =>
    splunkClient.get('/services/server/status') as Promise<SplunkEnvelope>,
}

// ── Search API ────────────────────────────────────────────────────────────

export const splunkSearchApi = {
  /** Create a search job. */
  createJob: (search: string, earliestTime = '', latestTime = ''): Promise<{ sid: string }> =>
    splunkClient.post('/services/search/jobs', {
      search, earliest_time: earliestTime, latest_time: latestTime,
    }) as Promise<{ sid: string }>,

  /** Get job status. */
  getJob: (sid: string): Promise<SplunkEnvelope<SplunkJobStatus>> =>
    splunkClient.get(`/services/search/jobs/${sid}`) as Promise<SplunkEnvelope<SplunkJobStatus>>,

  /** Get job results. */
  getResults: (sid: string, count = 100, offset = 0): Promise<SplunkSearchResults> =>
    splunkClient.get(`/services/search/v2/jobs/${sid}/results`, {
      params: { count, offset },
    }) as Promise<SplunkSearchResults>,

  /** One-shot export search. */
  exportSearch: (search: string): Promise<SplunkSearchResults> =>
    splunkClient.get('/services/search/jobs/export', {
      params: { search },
    }) as Promise<SplunkSearchResults>,
}

// ── Notable Events API ────────────────────────────────────────────────────

export const splunkNotableApi = {
  /** Fetch notable events by running the notable macro. */
  list: async (): Promise<SplunkNotable[]> => {
    const { sid } = await splunkSearchApi.createJob('`notable`')
    const results = await splunkSearchApi.getResults(sid, 200)
    return results.results as unknown as SplunkNotable[]
  },

  /** Update a notable event. */
  update: (eventId: string, data: Record<string, string>): Promise<unknown> =>
    splunkClient.post('/services/notable_update', {
      ruleUIDs: [eventId],
      ...data,
    }),
}

// ── Indexes API ───────────────────────────────────────────────────────────

export const splunkIndexApi = {
  /** List all indexes. */
  list: (): Promise<SplunkEnvelope<SplunkIndex>> =>
    splunkClient.get('/services/data/indexes') as Promise<SplunkEnvelope<SplunkIndex>>,
}

// ── HEC API ───────────────────────────────────────────────────────────────

export const splunkHecApi = {
  /** List HEC tokens. */
  listTokens: (): Promise<SplunkEnvelope<SplunkHecToken>> =>
    splunkClient.get('/servicesNS/nobody/splunk_httpinput/data/inputs/http') as Promise<SplunkEnvelope<SplunkHecToken>>,

  /** Submit a test event. */
  submitEvent: (token: string, event: Record<string, unknown>): Promise<SplunkHecResponse> =>
    axios.post('/splunk/services/collector/event', JSON.stringify({ event }), {
      headers: { 'Authorization': `Splunk ${token}`, 'Content-Type': 'application/json' },
    }).then(r => r.data) as Promise<SplunkHecResponse>,

  /** Check HEC health. */
  health: (): Promise<SplunkHecResponse> =>
    axios.get('/splunk/services/collector/health').then(r => r.data) as Promise<SplunkHecResponse>,
}

// ── Saved Searches API ────────────────────────────────────────────────────

export const splunkSavedSearchApi = {
  /** List saved searches. */
  list: (): Promise<SplunkEnvelope> =>
    splunkClient.get('/services/saved/searches') as Promise<SplunkEnvelope>,
}
