import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('axios', () => {
  const mockClient = {
    get: vi.fn().mockResolvedValue({ value: [], nextLink: '' }),
    post: vi.fn().mockResolvedValue({ value: [] }),
    put: vi.fn().mockResolvedValue({}),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
    headers: {},
  }
  return {
    default: {
      create: vi.fn(() => mockClient),
      post: vi.fn().mockResolvedValue({ data: { access_token: 'mock-token', expires_in: 3600, token_type: 'Bearer' } }),
      get: vi.fn().mockResolvedValue({ data: {} }),
      isAxiosError: vi.fn().mockReturnValue(false),
    },
  }
})

import {
  sentinelIncidentApi,
  sentinelWatchlistApi,
  sentinelThreatIntelApi,
  sentinelAlertRuleApi,
  sentinelOperationsApi,
} from '@/api/sentinel'

describe('sentinel API', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('sentinelIncidentApi.list returns promise', async () => {
    expect(sentinelIncidentApi.list()).toBeInstanceOf(Promise)
  })

  it('sentinelIncidentApi.list with top param', async () => {
    expect(sentinelIncidentApi.list(100)).toBeInstanceOf(Promise)
  })

  it('sentinelIncidentApi.get returns promise', async () => {
    expect(sentinelIncidentApi.get('inc-id')).toBeInstanceOf(Promise)
  })

  it('sentinelIncidentApi.update returns promise', async () => {
    expect(sentinelIncidentApi.update('inc-id', { status: 'Closed' })).toBeInstanceOf(Promise)
  })

  it('sentinelIncidentApi.getAlerts returns promise', async () => {
    expect(sentinelIncidentApi.getAlerts('inc-id')).toBeInstanceOf(Promise)
  })

  it('sentinelIncidentApi.getEntities returns promise', async () => {
    expect(sentinelIncidentApi.getEntities('inc-id')).toBeInstanceOf(Promise)
  })

  it('sentinelIncidentApi.getComments returns promise', async () => {
    expect(sentinelIncidentApi.getComments('inc-id')).toBeInstanceOf(Promise)
  })

  it('sentinelIncidentApi.addComment returns promise', async () => {
    expect(sentinelIncidentApi.addComment('inc-id', 'comment-id', 'Test comment')).toBeInstanceOf(Promise)
  })

  it('sentinelWatchlistApi.list returns promise', async () => {
    expect(sentinelWatchlistApi.list()).toBeInstanceOf(Promise)
  })

  it('sentinelThreatIntelApi.list returns promise', async () => {
    expect(sentinelThreatIntelApi.list()).toBeInstanceOf(Promise)
  })

  it('sentinelThreatIntelApi.list with top param', async () => {
    expect(sentinelThreatIntelApi.list(100)).toBeInstanceOf(Promise)
  })

  it('sentinelAlertRuleApi.list returns promise', async () => {
    expect(sentinelAlertRuleApi.list()).toBeInstanceOf(Promise)
  })

  it('sentinelOperationsApi.info returns promise', async () => {
    expect(sentinelOperationsApi.info()).toBeInstanceOf(Promise)
  })
})
