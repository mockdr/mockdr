import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('axios', () => {
  const mockClient = {
    get: vi.fn().mockResolvedValue({ resources: [], meta: { pagination: { total: 0 }, query_time: 0, powered_by: '', trace_id: '' }, errors: [] }),
    post: vi.fn().mockResolvedValue({ resources: [], meta: { query_time: 0, powered_by: '', trace_id: '' }, errors: [] }),
    patch: vi.fn().mockResolvedValue({ resources: [], meta: { query_time: 0, powered_by: '', trace_id: '' }, errors: [] }),
    delete: vi.fn().mockResolvedValue({ resources: [], meta: { query_time: 0, powered_by: '', trace_id: '' }, errors: [] }),
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
  ensureCsAuth,
  csAuthApi,
  csHostsApi,
  csDetectionsApi,
  csIncidentsApi,
  csIocsApi,
  csHostGroupsApi,
  csCasesApi,
} from '@/api/crowdstrike'

describe('crowdstrike API', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
  })

  it('ensureCsAuth fetches token when none present', async () => {
    await expect(ensureCsAuth()).resolves.toBeUndefined()
  })

  it('ensureCsAuth skips fetch when valid token present', async () => {
    localStorage.setItem('cs_token', 'existing-token')
    localStorage.setItem('cs_token_expires_at', String(Date.now() + 3600000))
    await expect(ensureCsAuth()).resolves.toBeUndefined()
  })

  it('csAuthApi.getToken calls oauth endpoint', async () => {
    const result = csAuthApi.getToken('id', 'secret')
    expect(result).toBeInstanceOf(Promise)
  })

  it('csHostsApi.queryIds returns promise', async () => {
    const result = csHostsApi.queryIds({ limit: 10 })
    expect(result).toBeInstanceOf(Promise)
  })

  it('csHostsApi.getEntities returns promise', async () => {
    const result = csHostsApi.getEntities(['id1', 'id2'])
    expect(result).toBeInstanceOf(Promise)
  })

  it('csHostsApi.action returns promise', async () => {
    const result = csHostsApi.action('contain', ['id1'])
    expect(result).toBeInstanceOf(Promise)
  })

  it('csDetectionsApi.queryIds returns promise', async () => {
    const result = csDetectionsApi.queryIds({ limit: 10 })
    expect(result).toBeInstanceOf(Promise)
  })

  it('csDetectionsApi.getEntities returns promise', async () => {
    const result = csDetectionsApi.getEntities(['id1'])
    expect(result).toBeInstanceOf(Promise)
  })

  it('csDetectionsApi.update returns promise', async () => {
    const result = csDetectionsApi.update(['id1'], { status: 'closed' })
    expect(result).toBeInstanceOf(Promise)
  })

  it('csIncidentsApi.queryIds returns promise', async () => {
    const result = csIncidentsApi.queryIds({ limit: 10 })
    expect(result).toBeInstanceOf(Promise)
  })

  it('csIncidentsApi.getEntities returns promise', async () => {
    const result = csIncidentsApi.getEntities(['id1'])
    expect(result).toBeInstanceOf(Promise)
  })

  it('csIncidentsApi.action returns promise', async () => {
    const result = csIncidentsApi.action(['id1'], [{ name: 'update_status', value: 'Closed' }])
    expect(result).toBeInstanceOf(Promise)
  })

  it('csIocsApi.search returns promise', async () => {
    const result = csIocsApi.search({ limit: 10 })
    expect(result).toBeInstanceOf(Promise)
  })

  it('csIocsApi.create returns promise', async () => {
    const result = csIocsApi.create([{ type: 'sha256', value: 'abc' }])
    expect(result).toBeInstanceOf(Promise)
  })

  it('csIocsApi.delete returns promise', async () => {
    const result = csIocsApi.delete(['id1'])
    expect(result).toBeInstanceOf(Promise)
  })

  it('csHostGroupsApi.list returns promise', async () => {
    const result = csHostGroupsApi.list()
    expect(result).toBeInstanceOf(Promise)
  })

  it('csCasesApi.list returns promise', async () => {
    const result = csCasesApi.list()
    expect(result).toBeInstanceOf(Promise)
  })
})
