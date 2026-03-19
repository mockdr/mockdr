import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('axios', () => {
  const mockClient = {
    get: vi.fn().mockResolvedValue({ value: [], '@odata.count': 0 }),
    post: vi.fn().mockResolvedValue({}),
    patch: vi.fn().mockResolvedValue({}),
    delete: vi.fn().mockResolvedValue(undefined),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
    headers: {},
  }
  return {
    default: {
      create: vi.fn(() => mockClient),
      post: vi.fn().mockResolvedValue({ data: { access_token: 'mock-token', expires_in: 3600, token_type: 'Bearer' } }),
      isAxiosError: vi.fn().mockReturnValue(false),
    },
  }
})

import {
  ensureMdeAuth,
  mdeMachinesApi,
  mdeAlertsApi,
  mdeIndicatorsApi,
  mdeSoftwareApi,
  mdeVulnerabilitiesApi,
} from '@/api/defender'

describe('defender API', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
  })

  it('ensureMdeAuth fetches token when none present', async () => {
    await expect(ensureMdeAuth()).resolves.toBeUndefined()
  })

  it('ensureMdeAuth skips fetch when valid token present', async () => {
    localStorage.setItem('mde_token', 'existing-token')
    localStorage.setItem('mde_token_expires_at', String(Date.now() + 3600000))
    await expect(ensureMdeAuth()).resolves.toBeUndefined()
  })

  it('mdeMachinesApi.list returns promise', async () => {
    expect(mdeMachinesApi.list()).toBeInstanceOf(Promise)
  })

  it('mdeMachinesApi.get returns promise', async () => {
    expect(mdeMachinesApi.get('machine-id')).toBeInstanceOf(Promise)
  })

  it('mdeMachinesApi.isolate returns promise', async () => {
    expect(mdeMachinesApi.isolate('machine-id', 'comment')).toBeInstanceOf(Promise)
  })

  it('mdeMachinesApi.unisolate returns promise', async () => {
    expect(mdeMachinesApi.unisolate('machine-id', 'comment')).toBeInstanceOf(Promise)
  })

  it('mdeMachinesApi.scanAction returns promise', async () => {
    expect(mdeMachinesApi.scanAction('machine-id', 'Quick')).toBeInstanceOf(Promise)
  })

  it('mdeAlertsApi.list returns promise', async () => {
    expect(mdeAlertsApi.list()).toBeInstanceOf(Promise)
  })

  it('mdeAlertsApi.get returns promise', async () => {
    expect(mdeAlertsApi.get('alert-id')).toBeInstanceOf(Promise)
  })

  it('mdeAlertsApi.update returns promise', async () => {
    expect(mdeAlertsApi.update('alert-id', { status: 'Resolved' })).toBeInstanceOf(Promise)
  })

  it('mdeIndicatorsApi.list returns promise', async () => {
    expect(mdeIndicatorsApi.list()).toBeInstanceOf(Promise)
  })

  it('mdeIndicatorsApi.get returns promise', async () => {
    expect(mdeIndicatorsApi.get('ind-id')).toBeInstanceOf(Promise)
  })

  it('mdeIndicatorsApi.create returns promise', async () => {
    expect(mdeIndicatorsApi.create({ indicatorValue: 'test' })).toBeInstanceOf(Promise)
  })

  it('mdeIndicatorsApi.update returns promise', async () => {
    expect(mdeIndicatorsApi.update('ind-id', { indicatorValue: 'test' })).toBeInstanceOf(Promise)
  })

  it('mdeIndicatorsApi.delete returns promise', async () => {
    expect(mdeIndicatorsApi.delete('ind-id')).toBeInstanceOf(Promise)
  })

  it('mdeSoftwareApi.list returns promise', async () => {
    expect(mdeSoftwareApi.list()).toBeInstanceOf(Promise)
  })

  it('mdeSoftwareApi.get returns promise', async () => {
    expect(mdeSoftwareApi.get('sw-id')).toBeInstanceOf(Promise)
  })

  it('mdeVulnerabilitiesApi.list returns promise', async () => {
    expect(mdeVulnerabilitiesApi.list()).toBeInstanceOf(Promise)
  })

  it('mdeVulnerabilitiesApi.get returns promise', async () => {
    expect(mdeVulnerabilitiesApi.get('vuln-id')).toBeInstanceOf(Promise)
  })
})
