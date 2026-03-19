import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('axios', () => {
  const mockClient = {
    get: vi.fn().mockResolvedValue({ entry: [], results: [] }),
    post: vi.fn().mockResolvedValue({ sid: 'test-sid', text: 'Success', code: 200 }),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
    headers: {},
  }
  return {
    default: {
      create: vi.fn(() => mockClient),
      post: vi.fn().mockResolvedValue({ data: { text: 'Success', code: 200 } }),
      get: vi.fn().mockResolvedValue({ data: { text: 'HEC is healthy' } }),
      isAxiosError: vi.fn().mockReturnValue(false),
    },
  }
})

import {
  splunkServerApi,
  splunkSearchApi,
  splunkNotableApi,
  splunkIndexApi,
  splunkHecApi,
  splunkSavedSearchApi,
} from '@/api/splunk'

describe('splunk API', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('splunkServerApi.info returns promise', async () => {
    expect(splunkServerApi.info()).toBeInstanceOf(Promise)
  })

  it('splunkServerApi.status returns promise', async () => {
    expect(splunkServerApi.status()).toBeInstanceOf(Promise)
  })

  it('splunkSearchApi.createJob returns promise', async () => {
    expect(splunkSearchApi.createJob('search *', '-15m', 'now')).toBeInstanceOf(Promise)
  })

  it('splunkSearchApi.getJob returns promise', async () => {
    expect(splunkSearchApi.getJob('test-sid')).toBeInstanceOf(Promise)
  })

  it('splunkSearchApi.getResults returns promise', async () => {
    expect(splunkSearchApi.getResults('test-sid', 50, 0)).toBeInstanceOf(Promise)
  })

  it('splunkSearchApi.exportSearch returns promise', async () => {
    expect(splunkSearchApi.exportSearch('search index=main')).toBeInstanceOf(Promise)
  })

  it('splunkNotableApi.update returns promise', async () => {
    expect(splunkNotableApi.update('event-id', { status: '2' })).toBeInstanceOf(Promise)
  })

  it('splunkIndexApi.list returns promise', async () => {
    expect(splunkIndexApi.list()).toBeInstanceOf(Promise)
  })

  it('splunkHecApi.listTokens returns promise', async () => {
    expect(splunkHecApi.listTokens()).toBeInstanceOf(Promise)
  })

  it('splunkHecApi.submitEvent returns promise', async () => {
    expect(splunkHecApi.submitEvent('test-token', { event: 'test' })).toBeInstanceOf(Promise)
  })

  it('splunkHecApi.health returns promise', async () => {
    expect(splunkHecApi.health()).toBeInstanceOf(Promise)
  })

  it('splunkSavedSearchApi.list returns promise', async () => {
    expect(splunkSavedSearchApi.list()).toBeInstanceOf(Promise)
  })
})
