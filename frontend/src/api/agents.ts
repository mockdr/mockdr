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

  /** Get a single agent by ID. */
  get: (id: string): Promise<SingleResponse<Agent>> =>
    client.get(`/agents/${id}`) as Promise<SingleResponse<Agent>>,

  /** Retrieve the decryption passphrase for an agent. */
  passphrase: (id: string): Promise<SingleResponse<{ passphrase: string }>> =>
    client.get(`/agents/${id}/passphrase`) as Promise<SingleResponse<{ passphrase: string }>>,

  /** List processes running on an agent. */
  processes: (id: string, params?: Record<string, unknown>): Promise<PaginatedResponse<AgentProcess>> =>
    client.get(`/agents/${id}/processes`, { params }) as Promise<PaginatedResponse<AgentProcess>>,

  /** List applications installed on an agent. */
  applications: (id: string, params?: Record<string, unknown>): Promise<PaginatedResponse<InstalledApp>> =>
    client.get(`/agents/${id}/applications`, { params }) as Promise<PaginatedResponse<InstalledApp>>,

  /** Trigger a bulk agent action (e.g. connect, disconnect, initiate-scan). */
  action: (action: string, body: unknown): Promise<ActionResponse> =>
    client.post(`/agents/actions/${action}`, body) as Promise<ActionResponse>,
}
