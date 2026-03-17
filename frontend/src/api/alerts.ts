import type { PaginatedResponse, SingleResponse, Alert, ActionResponse } from '../types'
import client from './client'

/** API methods for the /cloud-detection/alerts resource. */
export const alertsApi = {
  /** List alerts with optional filter/pagination params. */
  list: (params?: Record<string, unknown>): Promise<PaginatedResponse<Alert>> =>
    client.get('/cloud-detection/alerts', { params }) as Promise<PaginatedResponse<Alert>>,

  /** Get a single alert by ID. */
  get: (id: string): Promise<SingleResponse<Alert>> =>
    client.get(`/cloud-detection/alerts/${id}`) as Promise<SingleResponse<Alert>>,

  /** Trigger a bulk alert action. */
  action: (path: string, body: unknown): Promise<ActionResponse> =>
    client.post(`/alerts/${path}`, body) as Promise<ActionResponse>,
}
