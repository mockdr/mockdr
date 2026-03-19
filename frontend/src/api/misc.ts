import type {
  SitesListResponse,
  SingleResponse,
  PaginatedResponse,
  Account,
  Site,
  Group,
  Activity,
  Exclusion,
  BlocklistEntry,
  FirewallRule,
  DeviceControlRule,
  User,
  ActionResponse,
  DvEvent,
} from '../types'
import client from './client'

export const sitesApi = {
  /** List all sites (returns the special S1 sites envelope). */
  list: (params?: Record<string, unknown>): Promise<SitesListResponse> =>
    client.get('/sites', { params }) as Promise<SitesListResponse>,

  /** Get a single site by ID. */
  get: (id: string): Promise<SingleResponse<Site>> =>
    client.get(`/sites/${id}`) as Promise<SingleResponse<Site>>,

  /** Create a new site. Body is wrapped in {"data": {...}} per S1 API. */
  create: (data: Partial<Site> & Record<string, unknown>): Promise<SingleResponse<Site>> =>
    client.post('/sites', { data }) as Promise<SingleResponse<Site>>,

  /** Update an existing site. Only present fields are changed. */
  update: (id: string, data: Partial<Site> & Record<string, unknown>): Promise<SingleResponse<Site>> =>
    client.put(`/sites/${id}`, { data }) as Promise<SingleResponse<Site>>,

  /** Delete a site by ID. */
  delete: (id: string): Promise<{ data: { success: boolean } }> =>
    client.delete(`/sites/${id}`) as Promise<{ data: { success: boolean } }>,

  /** Reactivate an expired or decommissioned site. */
  reactivate: (id: string): Promise<SingleResponse<Site>> =>
    client.put(`/sites/${id}/reactivate`) as Promise<SingleResponse<Site>>,

  /** Immediately expire a trial site. */
  expire: (id: string): Promise<ActionResponse> =>
    client.post(`/sites/${id}/expire-now`) as Promise<ActionResponse>,
}

export const groupsApi = {
  /** List groups with optional filter params. */
  list: (params?: Record<string, unknown>): Promise<PaginatedResponse<Group>> =>
    client.get('/groups', { params }) as Promise<PaginatedResponse<Group>>,

  /** Create a new group. Body is wrapped in {"data": {...}} per S1 API. */
  create: (data: Partial<Group> & Record<string, unknown>): Promise<SingleResponse<Group>> =>
    client.post('/groups', { data }) as Promise<SingleResponse<Group>>,

  /** Update an existing group. Only present fields are changed. */
  update: (id: string, data: Partial<Group> & Record<string, unknown>): Promise<SingleResponse<Group>> =>
    client.put(`/groups/${id}`, { data }) as Promise<SingleResponse<Group>>,

  /** Delete a group by ID. */
  delete: (id: string): Promise<ActionResponse> =>
    client.delete(`/groups/${id}`) as Promise<ActionResponse>,
}

export const activitiesApi = {
  /** List activity log entries. */
  list: (params?: Record<string, unknown>): Promise<PaginatedResponse<Activity>> =>
    client.get('/activities', { params }) as Promise<PaginatedResponse<Activity>>,
}

export const exclusionsApi = {
  /** List path/hash exclusions. */
  list: (params?: Record<string, unknown>): Promise<PaginatedResponse<Exclusion>> =>
    client.get('/exclusions', { params }) as Promise<PaginatedResponse<Exclusion>>,

  /** Create a new exclusion. */
  create: (body: unknown): Promise<SingleResponse<Exclusion>> =>
    client.post('/exclusions', body) as Promise<SingleResponse<Exclusion>>,

  /** Delete an exclusion by ID. */
  delete: (id: string): Promise<ActionResponse> =>
    client.delete(`/exclusions/${id}`) as Promise<ActionResponse>,
}

export const blocklistApi = {
  /** List blocklist (hash restriction) entries. */
  list: (params?: Record<string, unknown>): Promise<PaginatedResponse<BlocklistEntry>> =>
    client.get('/restrictions', { params }) as Promise<PaginatedResponse<BlocklistEntry>>,

  /** Add a hash to the blocklist. */
  create: (body: Record<string, unknown>): Promise<SingleResponse<BlocklistEntry>> =>
    client.post('/restrictions', body) as Promise<SingleResponse<BlocklistEntry>>,

  /** Remove a blocklist entry by ID. */
  delete: (id: string): Promise<ActionResponse> =>
    client.delete(`/restrictions/${id}`) as Promise<ActionResponse>,
}

export const firewallApi = {
  /** List firewall control rules. */
  list: (params?: Record<string, unknown>): Promise<PaginatedResponse<FirewallRule>> =>
    client.get('/firewall-control', { params }) as Promise<PaginatedResponse<FirewallRule>>,

  /** Create a new firewall rule. Body: {data, filter} per S1 API. */
  create: (
    data: Partial<FirewallRule> & Record<string, unknown>,
    filter?: Record<string, unknown>,
  ): Promise<SingleResponse<FirewallRule>> =>
    client.post('/firewall-control', { data, filter: filter ?? {} }) as Promise<SingleResponse<FirewallRule>>,

  /** Update rules matching filter.ids. Body: {data, filter} per S1 API. */
  update: (
    id: string,
    data: Partial<FirewallRule> & Record<string, unknown>,
  ): Promise<SingleResponse<FirewallRule>> =>
    client.put('/firewall-control', { data, filter: { ids: [id] } }) as Promise<SingleResponse<FirewallRule>>,

  /** Delete rules matching filter.ids. */
  delete: (id: string): Promise<{ data: { affected: number } }> =>
    client.delete('/firewall-control', {
      data: { filter: { ids: [id] } },
    }) as Promise<{ data: { affected: number } }>,
}

export const deviceControlApi = {
  /** List device control rules. */
  list: (params?: Record<string, unknown>): Promise<PaginatedResponse<DeviceControlRule>> =>
    client.get('/device-control', { params }) as Promise<PaginatedResponse<DeviceControlRule>>,

  /** Create a new device control rule. Body: {data: {...}} per S1 API. */
  create: (data: Partial<DeviceControlRule> & Record<string, unknown>): Promise<SingleResponse<DeviceControlRule>> =>
    client.post('/device-control', { data }) as Promise<SingleResponse<DeviceControlRule>>,

  /** Update a device control rule by ID. Body: {data: {...}} per S1 API. */
  update: (id: string, data: Partial<DeviceControlRule> & Record<string, unknown>): Promise<SingleResponse<DeviceControlRule>> =>
    client.put(`/device-control/${id}`, { data }) as Promise<SingleResponse<DeviceControlRule>>,

  /** Delete device control rules by IDs. Body: {filter: {ids: [...]}} per S1 API. */
  delete: (id: string): Promise<{ data: { affected: number } }> =>
    client.delete('/device-control', {
      data: { filter: { ids: [id] } },
    }) as Promise<{ data: { affected: number } }>,
}

export const iocsApi = {
  list: (params?: Record<string, unknown>): Promise<PaginatedResponse<unknown>> =>
    client.get('/threat-intelligence/iocs', { params }) as Promise<PaginatedResponse<unknown>>,
  create: (body: unknown): Promise<SingleResponse<unknown>> =>
    client.post('/threat-intelligence/iocs', { data: body }) as Promise<SingleResponse<unknown>>,
  bulkCreate: (items: unknown[]): Promise<ActionResponse> =>
    client.post('/threat-intelligence/iocs/bulk', { data: items }) as Promise<ActionResponse>,
  delete: (ids: string[]): Promise<ActionResponse> =>
    client.delete('/threat-intelligence/iocs', {
      data: { filter: { ids } },
    }) as Promise<ActionResponse>,
}

interface DvQueryResult {
  queryId: string
}

interface DvQueryStatus {
  responseState: string
  progressPercentage: number
}

export const dvApi = {
  /** Initialise a Deep Visibility query and return a queryId. */
  initQuery: (body: unknown): Promise<SingleResponse<DvQueryResult>> =>
    client.post('/dv/init-query', body) as Promise<SingleResponse<DvQueryResult>>,

  /** Poll the status of a running DV query. */
  queryStatus: (queryId: string): Promise<SingleResponse<DvQueryStatus>> =>
    client.get('/dv/query-status', { params: { queryId } }) as Promise<SingleResponse<DvQueryStatus>>,

  /** Retrieve events for a completed DV query. */
  events: (queryId: string, params?: Record<string, unknown>): Promise<PaginatedResponse<DvEvent>> =>
    client.get('/dv/events', {
      params: { queryId, ...params },
    }) as Promise<PaginatedResponse<DvEvent>>,

  /** Cancel a running DV query. */
  cancel: (queryId: string): Promise<ActionResponse> =>
    client.post('/dv/cancel-query', { queryId }) as Promise<ActionResponse>,
}

export const accountsApi = {
  /** List all accounts. */
  list: (params?: Record<string, unknown>): Promise<PaginatedResponse<Account>> =>
    client.get('/accounts', { params }) as Promise<PaginatedResponse<Account>>,

  /** Get a single account by ID. */
  get: (id: string): Promise<SingleResponse<Account>> =>
    client.get(`/accounts/${id}`) as Promise<SingleResponse<Account>>,

  /** Create a new account. Body is wrapped in {"data": {...}} per S1 API. */
  create: (data: Partial<Account> & Record<string, unknown>): Promise<SingleResponse<Account>> =>
    client.post('/accounts', { data }) as Promise<SingleResponse<Account>>,

  /** Update an existing account. Only present fields are changed. */
  update: (id: string, data: Partial<Account> & Record<string, unknown>): Promise<SingleResponse<Account>> =>
    client.put(`/accounts/${id}`, { data }) as Promise<SingleResponse<Account>>,
}

export const usersApi = {
  /** List users with optional filter params. */
  list: (params?: Record<string, unknown>): Promise<PaginatedResponse<User>> =>
    client.get('/users', { params }) as Promise<PaginatedResponse<User>>,

  /** Get a single user by ID. */
  get: (id: string): Promise<SingleResponse<User>> =>
    client.get(`/users/${id}`) as Promise<SingleResponse<User>>,

  /** Create a new user. Response includes apiToken (only at creation). */
  create: (data: Record<string, unknown>): Promise<SingleResponse<User & { apiToken?: string }>> =>
    client.post('/users', { data }) as Promise<SingleResponse<User & { apiToken?: string }>>,

  /** Partially update a user. */
  update: (id: string, data: Record<string, unknown>): Promise<SingleResponse<User>> =>
    client.put(`/users/${id}`, { data }) as Promise<SingleResponse<User>>,

  /** Delete a user by ID. */
  delete: (id: string): Promise<{ data: { affected: number } }> =>
    client.delete(`/users/${id}`) as Promise<{ data: { affected: number } }>,

  /** Bulk-delete users by IDs. */
  bulkDelete: (ids: string[]): Promise<{ data: { affected: number } }> =>
    client.post('/users/delete-users', { filter: { ids } }) as Promise<{ data: { affected: number } }>,

  /** Regenerate the API token for the currently authenticated user. */
  generateApiToken: (): Promise<{ data: { token: string; expiresAt: string } }> =>
    client.post('/users/generate-api-token') as Promise<{ data: { token: string; expiresAt: string } }>,

  /** Get API token details for a user. */
  getApiTokenDetails: (id: string): Promise<{ data: { token: string; expiresAt: string | null } }> =>
    client.get(`/users/${id}/api-token-details`) as Promise<{ data: { token: string; expiresAt: string | null } }>,

  /** Authenticate by the token stored in the request header; returns current user. */
  loginByToken: (): Promise<SingleResponse<User>> =>
    client.get('/users/login/by-token') as Promise<SingleResponse<User>>,
}
