import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import RequestAuditView from '../RequestAuditView.vue'

const mockListRequests = vi.hoisted(() => vi.fn())

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../api/system', () => ({
  systemApi: {
    listRequests: mockListRequests,
    clearRequests: vi.fn(),
    status: vi.fn(),
    info: vi.fn(),
    getRateLimit: vi.fn(),
  },
  webhooksApi: { list: vi.fn() },
  proxyApi: { getConfig: vi.fn() },
}))

const FAKE_LOGS = [
  {
    id: 'req-1',
    method: 'GET',
    path: '/web/api/v2.1/agents',
    query_string: 'limit=25',
    status_code: 200,
    duration_ms: 12,
    token_hint: 'admin…0001',
    timestamp: '2025-06-01T12:00:00.000Z',
  },
  {
    id: 'req-2',
    method: 'POST',
    path: '/web/api/v2.1/threats/mark-as-threat',
    query_string: '',
    status_code: 200,
    duration_ms: 5,
    token_hint: 'soc…0003',
    timestamp: '2025-06-01T12:01:00.000Z',
  },
]

describe('RequestAuditView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockListRequests.mockResolvedValue({ data: FAKE_LOGS })
  })

  it('renders without error', async () => {
    const w = shallowMount(RequestAuditView)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the Request Audit Log heading', async () => {
    const w = shallowMount(RequestAuditView)
    await flushPromises()
    expect(w.text()).toContain('Request Audit Log')
  })

  it('calls listRequests on mount', async () => {
    shallowMount(RequestAuditView)
    await flushPromises()
    expect(mockListRequests).toHaveBeenCalledOnce()
  })

  it('renders request paths after load', async () => {
    const w = shallowMount(RequestAuditView)
    await flushPromises()
    expect(w.text()).toContain('/web/api/v2.1/agents')
    expect(w.text()).toContain('/web/api/v2.1/threats/mark-as-threat')
  })

  it('displays request count', async () => {
    const w = shallowMount(RequestAuditView)
    await flushPromises()
    expect(w.text()).toContain('2 of 2 requests')
  })

  it('renders search input', async () => {
    const w = shallowMount(RequestAuditView)
    await flushPromises()
    expect(w.find('input[type="text"]').exists()).toBe(true)
  })
})
