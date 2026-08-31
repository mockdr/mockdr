import type { PaginatedResponse, SingleResponse, Alert, ActionResponse } from '../types'
import client from './client'

/** API methods for the /cloud-detection/alerts resource. */
// There was a generic `action(path)` here, posting to `/alerts/<name>`.
// SentinelOne keeps its alert actions under `/cloud-detection/alerts/` and
// has nothing at `/alerts` at all, so every call 404'd. The two the vendor
// documents are named below.
export const alertsApi = {
  /** List alerts with optional filter/pagination params. */
  list: (params?: Record<string, unknown>): Promise<PaginatedResponse<Alert>> =>
    client.get('/cloud-detection/alerts', { params }) as Promise<PaginatedResponse<Alert>>,

  /** Get a single alert by ID. */
  get: (id: string): Promise<SingleResponse<Alert>> =>
    Promise.resolve(client.get('/cloud-detection/alerts', { params: { ids: id } }) as Promise<PaginatedResponse<Alert>>)
      .then((res) => ({ data: (res.data ?? [])[0] })),

  /** Set the analyst verdict for a list of alerts. */
  setVerdict: (ids: string[], analystVerdict: string): Promise<ActionResponse> =>
    client.post('/cloud-detection/alerts/analyst-verdict', {
      data: { analystVerdict },
      filter: { ids },
    }) as Promise<ActionResponse>,

  /** Set the incident status for a list of alerts. */
  setIncident: (ids: string[], incidentStatus: string): Promise<ActionResponse> =>
    client.post('/cloud-detection/alerts/incident', {
      data: { incidentStatus },
      filter: { ids },
    }) as Promise<ActionResponse>,
}
