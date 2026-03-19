import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('axios', () => {
  const mockClient = {
    post: vi.fn().mockResolvedValue({ reply: { total_count: 0, result_count: 0, incidents: [], alerts: [], endpoints: [], scripts: [], data: [] } }),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
    headers: {},
  }
  return {
    default: {
      create: vi.fn(() => mockClient),
      isAxiosError: vi.fn().mockReturnValue(false),
    },
  }
})

import {
  xdrIncidentsApi,
  xdrAlertsApi,
  xdrEndpointsApi,
  xdrHashExceptionsApi,
  xdrScriptsApi,
} from '@/api/cortex'

describe('cortex XDR API', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('xdrIncidentsApi.list returns promise', async () => {
    expect(xdrIncidentsApi.list()).toBeInstanceOf(Promise)
  })

  it('xdrIncidentsApi.list with filter', async () => {
    expect(xdrIncidentsApi.list({ field: 'status', operator: 'eq', value: 'new' })).toBeInstanceOf(Promise)
  })

  it('xdrIncidentsApi.getExtraData returns promise', async () => {
    expect(xdrIncidentsApi.getExtraData('inc-id')).toBeInstanceOf(Promise)
  })

  it('xdrIncidentsApi.update returns promise', async () => {
    expect(xdrIncidentsApi.update('inc-id', { status: 'resolved' })).toBeInstanceOf(Promise)
  })

  it('xdrAlertsApi.list returns promise', async () => {
    expect(xdrAlertsApi.list()).toBeInstanceOf(Promise)
  })

  it('xdrAlertsApi.list with filters', async () => {
    expect(xdrAlertsApi.list([{ field: 'severity', operator: 'eq', value: 'high' }])).toBeInstanceOf(Promise)
  })

  it('xdrEndpointsApi.list returns promise', async () => {
    expect(xdrEndpointsApi.list()).toBeInstanceOf(Promise)
  })

  it('xdrEndpointsApi.list with filters', async () => {
    expect(xdrEndpointsApi.list([{ field: 'endpoint_id', operator: 'in', value: ['ep-1'] }])).toBeInstanceOf(Promise)
  })

  it('xdrEndpointsApi.isolate returns promise', async () => {
    expect(xdrEndpointsApi.isolate('ep-id')).toBeInstanceOf(Promise)
  })

  it('xdrEndpointsApi.unisolate returns promise', async () => {
    expect(xdrEndpointsApi.unisolate('ep-id')).toBeInstanceOf(Promise)
  })

  it('xdrEndpointsApi.scan returns promise', async () => {
    expect(xdrEndpointsApi.scan('ep-id')).toBeInstanceOf(Promise)
  })

  it('xdrHashExceptionsApi.getBlocklist returns promise', async () => {
    expect(xdrHashExceptionsApi.getBlocklist()).toBeInstanceOf(Promise)
  })

  it('xdrHashExceptionsApi.getAllowlist returns promise', async () => {
    expect(xdrHashExceptionsApi.getAllowlist()).toBeInstanceOf(Promise)
  })

  it('xdrHashExceptionsApi.addToBlocklist returns promise', async () => {
    expect(xdrHashExceptionsApi.addToBlocklist([{ hash: 'abc123' }])).toBeInstanceOf(Promise)
  })

  it('xdrHashExceptionsApi.removeFromBlocklist returns promise', async () => {
    expect(xdrHashExceptionsApi.removeFromBlocklist(['abc123'])).toBeInstanceOf(Promise)
  })

  it('xdrHashExceptionsApi.addToAllowlist returns promise', async () => {
    expect(xdrHashExceptionsApi.addToAllowlist([{ hash: 'abc123' }])).toBeInstanceOf(Promise)
  })

  it('xdrHashExceptionsApi.removeFromAllowlist returns promise', async () => {
    expect(xdrHashExceptionsApi.removeFromAllowlist(['abc123'])).toBeInstanceOf(Promise)
  })

  it('xdrScriptsApi.list returns promise', async () => {
    expect(xdrScriptsApi.list()).toBeInstanceOf(Promise)
  })
})
