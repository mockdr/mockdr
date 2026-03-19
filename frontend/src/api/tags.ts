import type { PaginatedResponse, ActionResponse } from '../types'
import type { TagDefinition } from '../types'
import client from './client'

/** API methods for tag management. */
export const tagsApi = {
  /** List tag definitions with optional filter/pagination params. */
  list: (params?: Record<string, unknown>): Promise<PaginatedResponse<TagDefinition>> =>
    client.get('/agents/tags', { params }) as Promise<PaginatedResponse<TagDefinition>>,

  /** Create a new tag definition. */
  create: (body: unknown): Promise<{ data: TagDefinition }> =>
    client.post('/tag-manager', body) as Promise<{ data: TagDefinition }>,

  /** Update a tag definition. */
  update: (id: string, body: unknown): Promise<{ data: TagDefinition }> =>
    client.put(`/tag-manager/${id}`, body) as Promise<{ data: TagDefinition }>,

  /** Delete a tag definition. */
  delete: (id: string): Promise<ActionResponse> =>
    client.delete(`/tag-manager/${id}`) as Promise<ActionResponse>,
}
