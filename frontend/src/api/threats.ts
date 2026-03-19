import type {
  PaginatedResponse,
  SingleResponse,
  ActionResponse,
  ThreatRecord,
} from '../types'
import client from './client'

interface TimelineEvent {
  id: string
  timestamp: string
  event: string
  type: string
}

interface ThreatNote {
  id: string
  text: string
  createdAt: string
}

/** API methods for the /threats resource. */
export const threatsApi = {
  /** List threats with optional filter/pagination params. */
  list: (params?: Record<string, unknown>): Promise<PaginatedResponse<ThreatRecord>> =>
    client.get('/threats', { params }) as Promise<PaginatedResponse<ThreatRecord>>,

  /** Get a single threat by ID. */
  get: (id: string): Promise<SingleResponse<ThreatRecord>> =>
    client.get(`/threats/${id}`) as Promise<SingleResponse<ThreatRecord>>,

  /** Get the threat event timeline. */
  timeline: (id: string): Promise<PaginatedResponse<TimelineEvent>> =>
    client.get(`/threats/${id}/timeline`) as Promise<PaginatedResponse<TimelineEvent>>,

  /** List analyst notes on a threat. */
  getNotes: (id: string): Promise<PaginatedResponse<ThreatNote>> =>
    client.get(`/threats/${id}/notes`) as Promise<PaginatedResponse<ThreatNote>>,

  /** Add an analyst note to a threat. */
  addNote: (id: string, text: string): Promise<SingleResponse<ThreatNote>> =>
    client.post(`/threats/${id}/notes`, { text }) as Promise<SingleResponse<ThreatNote>>,

  /** Set the analyst verdict for a list of threats. */
  setVerdict: (ids: string[], verdict: string): Promise<ActionResponse> =>
    client.post('/threats/analyst-verdict', {
      data: { verdict },
      filter: { ids },
    }) as Promise<ActionResponse>,

  /** Set the incident status for a list of threats. */
  setIncident: (ids: string[], status: string): Promise<ActionResponse> =>
    client.post('/threats/incident', {
      data: { incidentStatus: status },
      filter: { ids },
    }) as Promise<ActionResponse>,

  /** Apply a mitigation action to a list of threats. */
  mitigate: (action: string, ids: string[]): Promise<ActionResponse> =>
    client.post(`/threats/mitigate/${action}`, { filter: { ids } }) as Promise<ActionResponse>,

  /** Add a list of threats to the blocklist. */
  addToBlacklist: (ids: string[]): Promise<ActionResponse> =>
    client.post('/threats/add-to-blacklist', {
      data: { targetScope: 'site' },
      filter: { ids },
    }) as Promise<ActionResponse>,

  /** Generic bulk action (e.g. mark-as-threat, mark-as-benign, resolve). */
  action: (actionPath: string, body: unknown): Promise<ActionResponse> =>
    client.post(`/threats/actions/${actionPath}`, body) as Promise<ActionResponse>,
}
