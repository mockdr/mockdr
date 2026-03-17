import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import RateLimitView from '../RateLimitView.vue'

const mockGetRateLimit = vi.hoisted(() => vi.fn())

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../api/system', () => ({
  systemApi: {
    getRateLimit: mockGetRateLimit,
    setRateLimit: vi.fn(),
    status: vi.fn(),
    info: vi.fn(),
    listRequests: vi.fn(),
  },
  webhooksApi: { list: vi.fn() },
  proxyApi: { getConfig: vi.fn() },
}))

const FAKE_CONFIG = {
  enabled: true,
  requests_per_minute: 120,
  active_counters: 3,
}

describe('RateLimitView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetRateLimit.mockResolvedValue({ data: FAKE_CONFIG })
  })

  it('renders without error', async () => {
    const w = shallowMount(RateLimitView)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the Rate-Limit heading', async () => {
    const w = shallowMount(RateLimitView)
    await flushPromises()
    expect(w.text()).toContain('Rate-Limit Simulation')
  })

  it('calls getRateLimit on mount', async () => {
    shallowMount(RateLimitView)
    await flushPromises()
    expect(mockGetRateLimit).toHaveBeenCalledOnce()
  })

  it('displays the current config values', async () => {
    const w = shallowMount(RateLimitView)
    await flushPromises()
    expect(w.text()).toContain('ON')
    expect(w.text()).toContain('120')
    expect(w.text()).toContain('3')
  })

  it('shows RPM presets', async () => {
    const w = shallowMount(RateLimitView)
    await flushPromises()
    expect(w.text()).toContain('60/min')
    expect(w.text()).toContain('300/min')
  })
})
