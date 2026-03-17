import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import RecordingProxyView from '../RecordingProxyView.vue'

const mockGetConfig = vi.hoisted(() => vi.fn())
const mockListRecordings = vi.hoisted(() => vi.fn())

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../api/system', () => ({
  proxyApi: {
    getConfig: mockGetConfig,
    setConfig: vi.fn(),
    listRecordings: mockListRecordings,
    clearRecordings: vi.fn(),
  },
  systemApi: { status: vi.fn(), info: vi.fn(), listRequests: vi.fn(), getRateLimit: vi.fn() },
  webhooksApi: { list: vi.fn() },
}))

const FAKE_CONFIG = {
  mode: 'off',
  base_url: 'https://tenant.sentinelone.net',
  api_token: '***redacted***',
  recording_count: 5,
}

const FAKE_RECORDINGS = [
  {
    id: 'rec-1',
    method: 'GET',
    path: '/web/api/v2.1/agents',
    query_string: 'limit=10',
    response_status: 200,
    response_content_type: 'application/json',
    recorded_at: '2025-06-01T12:00:00Z',
  },
  {
    id: 'rec-2',
    method: 'POST',
    path: '/web/api/v2.1/threats/mark-as-threat',
    query_string: '',
    response_status: 200,
    response_content_type: 'application/json',
    recorded_at: '2025-06-01T12:01:00Z',
  },
]

describe('RecordingProxyView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetConfig.mockResolvedValue({ data: FAKE_CONFIG })
    mockListRecordings.mockResolvedValue({ data: FAKE_RECORDINGS })
  })

  it('renders without error', async () => {
    const w = shallowMount(RecordingProxyView)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the Recording Proxy heading', async () => {
    const w = shallowMount(RecordingProxyView)
    await flushPromises()
    expect(w.text()).toContain('Recording Proxy')
  })

  it('loads config and recordings on mount', async () => {
    shallowMount(RecordingProxyView)
    await flushPromises()
    expect(mockGetConfig).toHaveBeenCalledOnce()
    expect(mockListRecordings).toHaveBeenCalledOnce()
  })

  it('displays recording paths', async () => {
    const w = shallowMount(RecordingProxyView)
    await flushPromises()
    expect(w.text()).toContain('/web/api/v2.1/agents')
    expect(w.text()).toContain('/web/api/v2.1/threats/mark-as-threat')
  })

  it('shows mode buttons', async () => {
    const w = shallowMount(RecordingProxyView)
    await flushPromises()
    expect(w.text()).toContain('off')
    expect(w.text()).toContain('record')
    expect(w.text()).toContain('replay')
  })

  it('displays recording count in stats', async () => {
    const w = shallowMount(RecordingProxyView)
    await flushPromises()
    expect(w.text()).toContain('5')
  })
})
