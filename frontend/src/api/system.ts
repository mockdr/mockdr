import type { SingleResponse, SystemStats, RequestLog, WebhookSubscription, RateLimitConfig, ProxyConfig, ProxyRecording, VendorInfo } from '../types'
import client from './client'

interface SystemStatus {
  status: string
}

interface SystemInfo {
  version: string
  [key: string]: unknown
}

interface TokenEntry {
  label: string
  token: string
  role: string
}

/** API methods for dev/system endpoints (not part of the real S1 API). */
export const systemApi = {
  /** Get server liveness status. */
  status: (): Promise<SingleResponse<SystemStatus>> =>
    client.get('/system/status') as Promise<SingleResponse<SystemStatus>>,

  /** Get server version info. */
  info: (): Promise<SingleResponse<SystemInfo>> =>
    client.get('/system/info') as Promise<SingleResponse<SystemInfo>>,

  /** Get in-memory store counts for the dev panel. */
  stats: (): Promise<SingleResponse<SystemStats>> =>
    client.get('/_dev/stats') as Promise<SingleResponse<SystemStats>>,

  /** Get all available test API tokens. */
  tokens: (): Promise<SingleResponse<TokenEntry[]>> =>
    client.get('/_dev/tokens') as Promise<SingleResponse<TokenEntry[]>>,

  /** Reset the in-memory store to the deterministic seed. */
  reset: (): Promise<SingleResponse<unknown>> =>
    client.post('/_dev/reset') as Promise<SingleResponse<unknown>>,

  /** Apply a named scenario (e.g. mass_infection, quiet_day). */
  scenario: (scenario: string): Promise<SingleResponse<unknown>> =>
    client.post('/_dev/scenario', { scenario }) as Promise<SingleResponse<unknown>>,

  /** List request audit log entries (newest first). */
  listRequests: (): Promise<SingleResponse<RequestLog[]>> =>
    client.get('/_dev/requests') as Promise<SingleResponse<RequestLog[]>>,

  /** Clear all request audit log entries. */
  clearRequests: (): Promise<SingleResponse<unknown>> =>
    client.delete('/_dev/requests') as Promise<SingleResponse<unknown>>,

  /** Export full store snapshot as JSON. */
  exportState: (): Promise<SingleResponse<unknown>> =>
    client.get('/_dev/export') as Promise<SingleResponse<unknown>>,

  /** Import a store snapshot. */
  importState: (snapshot: unknown): Promise<SingleResponse<unknown>> =>
    client.post('/_dev/import', snapshot) as Promise<SingleResponse<unknown>>,

  /** Get current rate-limit configuration. */
  getRateLimit: (): Promise<SingleResponse<RateLimitConfig>> =>
    client.get('/_dev/rate-limit') as Promise<SingleResponse<RateLimitConfig>>,

  /** Update rate-limit configuration. */
  setRateLimit: (cfg: Partial<RateLimitConfig>): Promise<SingleResponse<RateLimitConfig>> =>
    client.post('/_dev/rate-limit', cfg) as Promise<SingleResponse<RateLimitConfig>>,
}

/** Recording proxy management API. */
export const proxyApi = {
  getConfig: (): Promise<SingleResponse<ProxyConfig>> =>
    client.get('/_dev/proxy/config') as Promise<SingleResponse<ProxyConfig>>,

  setConfig: (cfg: object): Promise<SingleResponse<ProxyConfig>> =>
    client.post('/_dev/proxy/config', cfg) as Promise<SingleResponse<ProxyConfig>>,

  listRecordings: (): Promise<{ data: ProxyRecording[]; pagination: { totalItems: number } }> =>
    client.get('/_dev/proxy/recordings') as Promise<{ data: ProxyRecording[]; pagination: { totalItems: number } }>,

  clearRecordings: (): Promise<SingleResponse<{ cleared: number }>> =>
    client.delete('/_dev/proxy/recordings') as Promise<SingleResponse<{ cleared: number }>>,

  listVendors: (): Promise<SingleResponse<VendorInfo[]>> =>
    client.get('/_dev/proxy/vendors') as Promise<SingleResponse<VendorInfo[]>>,
}

/** Webhook management API. */
export const webhooksApi = {
  /** List all webhook subscriptions. */
  list: (): Promise<SingleResponse<WebhookSubscription[]>> =>
    client.get('/webhooks') as Promise<SingleResponse<WebhookSubscription[]>>,

  /** Create a webhook subscription. */
  create: (payload: Partial<WebhookSubscription>): Promise<SingleResponse<WebhookSubscription>> =>
    client.post('/webhooks', payload) as Promise<SingleResponse<WebhookSubscription>>,

  /** Delete a webhook subscription. */
  delete: (id: string): Promise<SingleResponse<unknown>> =>
    client.delete(`/webhooks/${id}`) as Promise<SingleResponse<unknown>>,

  /** Fire a test event to all matching subscriptions. */
  fire: (event_type: string, payload?: unknown): Promise<SingleResponse<unknown>> =>
    client.post('/webhooks/fire', { event_type, payload }) as Promise<SingleResponse<unknown>>,
}
