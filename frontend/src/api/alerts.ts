import type { PaginatedResponse, SingleResponse, Alert, ActionResponse } from '../types'
import client from './client'

/** API methods for the /cloud-detection/alerts resource. */
export const alertsApi = {
  /** List alerts with optional filter/pagination params. */
  list: (params?: Record<string, unknown>): Promise<PaginatedResponse<Alert>> =>
    client.get('/cloud-detection/alerts', { params }) as Promise<PaginatedResponse<Alert>>,

  /** Get a single alert by ID. */
  get: (id: string): Promise<SingleResponse<Alert>> =>
    Promise.resolve(client.get('/cloud-detection/alerts', { params: { ids: id } }) as Promise<PaginatedResponse<Alert>>)
      .then((res) => ({ data: (res.data ?? [])[0] })),

  /** Trigger a bulk alert action. */
  action: (path: string, body: unknown): Promise<ActionResponse> =>
    client.post(`/alerts/${path}`, body) as Promise<ActionResponse>,
}
