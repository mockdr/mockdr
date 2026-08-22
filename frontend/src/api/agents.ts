import type {
  PaginatedResponse,
  SingleResponse,
  ActionResponse,
  Agent,
  InstalledApp,
  AgentProcess,
} from '../types'
import client from './client'

/** API methods for the /agents resource. */
export const agentsApi = {
  /** List agents with optional filter/pagination params. */
  list: (params?: Record<string, unknown>): Promise<PaginatedResponse<Agent>> =>
    client.get('/agents', { params }) as Promise<PaginatedResponse<Agent>>,

  /** Get a single agent by ID — the 2.1 API has no /agents/{id}; it is a filtered list. */
  get: (id: string): Promise<SingleResponse<Agent>> =>
    Promise.resolve(client.get('/agents', { params: { ids: id } }) as Promise<PaginatedResponse<Agent>>)
      .then((res) => ({ data: res.data[0] })),

  /** Retrieve the decryption passphrase for an agent (``/agents/passphrases?ids=``). */
  passphrase: (id: string): Promise<SingleResponse<{ passphrase: string }>> =>
    Promise.resolve(client.get('/agents/passphrases', { params: { ids: id } }) as Promise<PaginatedResponse<{ passphrase: string }>>)
      .then((res) => ({ data: res.data[0] })),

  /** List processes running on an agent (``/agents/processes?ids=``; no pagination block). */
  processes: (id: string, params?: Record<string, unknown>): Promise<SingleResponse<AgentProcess[]>> =>
    client.get('/agents/processes', { params: { ...params, ids: id } }) as Promise<SingleResponse<AgentProcess[]>>,

  /** List applications installed on an agent (``/agents/applications?ids=``; no pagination block). */
  applications: (id: string, params?: Record<string, unknown>): Promise<SingleResponse<InstalledApp[]>> =>
    client.get('/agents/applications', { params: { ...params, ids: id } }) as Promise<SingleResponse<InstalledApp[]>>,

  /** Trigger a bulk agent action (e.g. connect, disconnect, initiate-scan). */
  action: (action: string, body: unknown): Promise<ActionResponse> =>
    client.post(`/agents/actions/${action}`, body) as Promise<ActionResponse>,
}
