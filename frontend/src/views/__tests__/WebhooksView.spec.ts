import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import WebhooksView from '../WebhooksView.vue'

const mockList = vi.hoisted(() => vi.fn())

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../api/system', () => ({
  webhooksApi: {
    list: mockList,
    create: vi.fn(),
    delete: vi.fn(),
    fire: vi.fn(),
  },
  systemApi: {
    status: vi.fn(),
    info: vi.fn(),
    getRateLimit: vi.fn(),
    listRequests: vi.fn(),
  },
  proxyApi: { getConfig: vi.fn(), listRecordings: vi.fn() },
}))

const FAKE_HOOKS = [
  {
    id: 'wh-1',
    url: 'https://hooks.example.com/s1',
    description: 'SOAR webhook',
    active: true,
    event_types: ['threat.created', 'threat.updated'],
    created_at: '2025-05-10T12:00:00Z',
  },
  {
    id: 'wh-2',
    url: 'https://siem.internal/webhook',
    description: '',
    active: false,
    event_types: ['alert.created'],
    created_at: '2025-06-01T09:00:00Z',
  },
]

describe('WebhooksView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockList.mockResolvedValue({ data: FAKE_HOOKS })
  })

  it('renders without error', async () => {
    const w = shallowMount(WebhooksView)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the Webhook Subscriptions heading', async () => {
    const w = shallowMount(WebhooksView)
    await flushPromises()
    expect(w.text()).toContain('Webhook Subscriptions')
  })

  it('calls webhooksApi.list on mount', async () => {
    shallowMount(WebhooksView)
    await flushPromises()
    expect(mockList).toHaveBeenCalledOnce()
  })

  it('renders webhook URLs after load', async () => {
    const w = shallowMount(WebhooksView)
    await flushPromises()
    expect(w.text()).toContain('https://hooks.example.com/s1')
    expect(w.text()).toContain('https://siem.internal/webhook')
  })

  it('displays registered endpoint count', async () => {
    const w = shallowMount(WebhooksView)
    await flushPromises()
    expect(w.text()).toContain('2 registered endpoints')
  })

  it('renders fire test event buttons', async () => {
    const w = shallowMount(WebhooksView)
    await flushPromises()
    expect(w.text()).toContain('Fire Test Event')
    expect(w.text()).toContain('threat.created')
  })
})
