import axios from 'axios'
import type {
  EsSearchResponse,
  KibanaListResponse,
  EsEndpoint,
  EsRule,
  EsAlert,
  EsCase,
  EsCaseComment,
  EsExceptionList,
  EsExceptionListItem,
} from '../types/elastic'

const esBasicAuth = 'Basic ' + btoa(`${import.meta.env.VITE_ES_USERNAME}:${import.meta.env.VITE_ES_PASSWORD}`)

/**
 * Axios instance for Elasticsearch mock API.
 * Uses Basic Auth and the `/elastic` prefix.
 */
const esClient = axios.create({
  baseURL: '/elastic',
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
    'Authorization': esBasicAuth,
  },
})

esClient.interceptors.response.use(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (response): any => response.data,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('es_token')
    }
    return Promise.reject(error)
  },
)

/**
 * Axios instance for Kibana mock API.
 * Uses Basic Auth, the `/kibana` prefix, and the kbn-xsrf header.
 */
const kbnClient = axios.create({
  baseURL: '/kibana',
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
    'Authorization': esBasicAuth,
    'kbn-xsrf': 'true',
  },
})

kbnClient.interceptors.response.use(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (response): any => response.data,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('es_token')
    }
    return Promise.reject(error)
  },
)

// ── Search API ──────────────────────────────────────────────────────────────

export const esSearchApi = {
  /** Execute a search against an index. */
  search: <T>(index: string, body: Record<string, unknown>): Promise<EsSearchResponse<T>> =>
    esClient.post(`/${index}/_search`, body) as Promise<EsSearchResponse<T>>,

  /** Get cluster info. */
  clusterInfo: (): Promise<Record<string, unknown>> =>
    esClient.get('/') as Promise<Record<string, unknown>>,
}

// ── Endpoints API ───────────────────────────────────────────────────────────

export const esEndpointsApi = {
  /** List endpoint metadata. */
  list: (params?: Record<string, unknown>): Promise<KibanaListResponse<EsEndpoint>> =>
    kbnClient.get('/api/endpoint/metadata', { params }) as Promise<KibanaListResponse<EsEndpoint>>,

  /** Get single endpoint metadata. */
  get: (id: string): Promise<EsEndpoint> =>
    kbnClient.get(`/api/endpoint/metadata/${id}`) as Promise<EsEndpoint>,

  /** Isolate an endpoint. */
  isolate: (agentIds: string[], comment: string): Promise<unknown> =>
    kbnClient.post('/api/endpoint/action/isolate', { endpoint_ids: agentIds, comment }),

  /** Release from isolation. */
  unisolate: (agentIds: string[], comment: string): Promise<unknown> =>
    kbnClient.post('/api/endpoint/action/unisolate', { endpoint_ids: agentIds, comment }),
}

// ── Detection Rules API ─────────────────────────────────────────────────────

export const esRulesApi = {
  /** Find detection rules. */
  find: (params?: Record<string, unknown>): Promise<KibanaListResponse<EsRule>> =>
    kbnClient.get('/api/detection_engine/rules/_find', { params }) as Promise<KibanaListResponse<EsRule>>,

  /** Get a single rule by ID. */
  get: (id: string): Promise<EsRule> =>
    kbnClient.get('/api/detection_engine/rules', { params: { id } }) as Promise<EsRule>,

  /** Create a detection rule. */
  create: (body: Partial<EsRule>): Promise<EsRule> =>
    kbnClient.post('/api/detection_engine/rules', body) as Promise<EsRule>,

  /** Update a detection rule. */
  update: (body: Partial<EsRule>): Promise<EsRule> =>
    kbnClient.put('/api/detection_engine/rules', body) as Promise<EsRule>,

  /** Delete a detection rule. */
  delete: (id: string): Promise<unknown> =>
    kbnClient.delete('/api/detection_engine/rules', { params: { id } }),

  /** Get rule tags. */
  tags: (): Promise<string[]> =>
    kbnClient.get('/api/detection_engine/tags') as Promise<string[]>,

  /** Bulk action on rules. */
  bulkAction: (body: Record<string, unknown>): Promise<unknown> =>
    kbnClient.post('/api/detection_engine/rules/_bulk_action', body),
}

// ── Alerts (Signals) API ────────────────────────────────────────────────────

export const esAlertsApi = {
  /** Search alerts/signals. */
  search: (body: Record<string, unknown>): Promise<EsSearchResponse<EsAlert>> =>
    kbnClient.post('/api/detection_engine/signals/search', body) as Promise<EsSearchResponse<EsAlert>>,

  /** Update alert status. */
  updateStatus: (body: Record<string, unknown>): Promise<unknown> =>
    kbnClient.post('/api/detection_engine/signals/status', body),

  /** Update alert tags. */
  updateTags: (body: Record<string, unknown>): Promise<unknown> =>
    kbnClient.post('/api/detection_engine/signals/tags', body),
}

// ── Cases API ───────────────────────────────────────────────────────────────

export const esCasesApi = {
  /** Find cases. */
  find: (params?: Record<string, unknown>): Promise<KibanaListResponse<EsCase>> =>
    kbnClient.get('/api/cases/_find', { params }) as Promise<KibanaListResponse<EsCase>>,

  /** Get a single case. */
  get: (id: string): Promise<EsCase> =>
    kbnClient.get(`/api/cases/${id}`) as Promise<EsCase>,

  /** Create a case. */
  create: (body: Record<string, unknown>): Promise<EsCase> =>
    kbnClient.post('/api/cases', body) as Promise<EsCase>,

  /** Update a case. */
  update: (body: Record<string, unknown>): Promise<EsCase[]> =>
    kbnClient.patch('/api/cases', body) as Promise<EsCase[]>,

  /** Delete cases. */
  delete: (ids: string[]): Promise<unknown> =>
    kbnClient.delete('/api/cases', { params: { ids: ids.join(',') } }),

  /** Add a comment to a case. */
  addComment: (caseId: string, body: Record<string, unknown>): Promise<EsCaseComment> =>
    kbnClient.post(`/api/cases/${caseId}/comments`, body) as Promise<EsCaseComment>,

  /** Get comments for a case. */
  getComments: (caseId: string): Promise<KibanaListResponse<EsCaseComment>> =>
    kbnClient.get(`/api/cases/${caseId}/comments`) as Promise<KibanaListResponse<EsCaseComment>>,
}

// ── Exception Lists API ─────────────────────────────────────────────────────

export const esExceptionListsApi = {
  /** Find exception lists. */
  findLists: (params?: Record<string, unknown>): Promise<KibanaListResponse<EsExceptionList>> =>
    kbnClient.get('/api/exception_lists/_find', { params }) as Promise<KibanaListResponse<EsExceptionList>>,

  /** Find exception list items. */
  findItems: (params?: Record<string, unknown>): Promise<KibanaListResponse<EsExceptionListItem>> =>
    kbnClient.get('/api/exception_lists/items/_find', { params }) as Promise<KibanaListResponse<EsExceptionListItem>>,

  /** Create an exception list. */
  createList: (body: Record<string, unknown>): Promise<EsExceptionList> =>
    kbnClient.post('/api/exception_lists', body) as Promise<EsExceptionList>,

  /** Delete an exception list. */
  deleteList: (id: string, namespaceType: string): Promise<unknown> =>
    kbnClient.delete('/api/exception_lists', { params: { id, namespace_type: namespaceType } }),

  /** Create an exception list item. */
  createItem: (body: Record<string, unknown>): Promise<EsExceptionListItem> =>
    kbnClient.post('/api/exception_lists/items', body) as Promise<EsExceptionListItem>,

  /** Delete an exception list item. */
  deleteItem: (id: string, namespaceType: string): Promise<unknown> =>
    kbnClient.delete('/api/exception_lists/items', { params: { id, namespace_type: namespaceType } }),
}
