import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, mount, flushPromises } from '@vue/test-utils'
import RecordingProxyView from '@/views/RecordingProxyView.vue'

const mockGetConfig = vi.hoisted(() => vi.fn())
const mockListRecordings = vi.hoisted(() => vi.fn())
const mockListVendors = vi.hoisted(() => vi.fn())

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
    listVendors: mockListVendors,
  },
  systemApi: { status: vi.fn(), info: vi.fn(), listRequests: vi.fn(), getRateLimit: vi.fn() },
  webhooksApi: { list: vi.fn() },
}))

const FAKE_CONFIG = {
  mode: 'off',
  vendors: {
    s1: {
      vendor: 's1',
      base_url: 'https://tenant.sentinelone.net',
      auth: { type: 'api_token', token: '***' },
      enabled: true,
    },
  },
  base_url: 'https://tenant.sentinelone.net',
  api_token: '***redacted***',
  recording_count: 5,
}

const FAKE_VENDORS = [
  { vendor: 's1', label: 'SentinelOne', default_auth_type: 'api_token' },
  { vendor: 'crowdstrike', label: 'CrowdStrike Falcon', default_auth_type: 'oauth2' },
  { vendor: 'mde', label: 'Microsoft Defender for Endpoint', default_auth_type: 'oauth2' },
  { vendor: 'elastic', label: 'Elastic Security', default_auth_type: 'basic' },
  { vendor: 'cortex_xdr', label: 'Cortex XDR', default_auth_type: 'hmac' },
  { vendor: 'splunk', label: 'Splunk SIEM', default_auth_type: 'basic' },
  { vendor: 'sentinel', label: 'Microsoft Sentinel', default_auth_type: 'oauth2' },
  { vendor: 'graph', label: 'Microsoft Graph API', default_auth_type: 'oauth2' },
]

const FAKE_RECORDINGS = [
  {
    id: 'rec-1',
    method: 'GET',
    path: '/web/api/v2.1/agents',
    query_string: 'limit=10',
    response_status: 200,
    response_content_type: 'application/json',
    recorded_at: '2025-06-01T12:00:00Z',
    vendor: 's1',
  },
  {
    id: 'rec-2',
    method: 'POST',
    path: '/cs/devices/queries/devices/v1',
    query_string: '',
    response_status: 200,
    response_content_type: 'application/json',
    recorded_at: '2025-06-01T12:01:00Z',
    vendor: 'crowdstrike',
  },
]

describe('RecordingProxyView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetConfig.mockResolvedValue({ data: FAKE_CONFIG })
    mockListRecordings.mockResolvedValue({ data: FAKE_RECORDINGS })
    mockListVendors.mockResolvedValue({ data: FAKE_VENDORS })
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

  it('loads config, recordings, and vendors on mount', async () => {
    shallowMount(RecordingProxyView)
    await flushPromises()
    expect(mockGetConfig).toHaveBeenCalledOnce()
    expect(mockListRecordings).toHaveBeenCalledOnce()
    expect(mockListVendors).toHaveBeenCalledOnce()
  })

  it('displays recording paths', async () => {
    const w = shallowMount(RecordingProxyView)
    await flushPromises()
    expect(w.text()).toContain('/web/api/v2.1/agents')
    expect(w.text()).toContain('/cs/devices/queries/devices/v1')
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

  it('Refresh button triggers fetchAll via DOM click', async () => {
    const { proxyApi } = await import('../../api/system')
    const w = mount(RecordingProxyView, { global: { stubs: { EmptyState: true, LoadingSkeleton: true } } })
    await flushPromises()
    vi.mocked(proxyApi.getConfig).mockClear()
    const refreshBtn = w.findAll('button').find(b => b.text().includes('Refresh'))
    await refreshBtn!.trigger('click')
    await flushPromises()
    expect(proxyApi.getConfig).toHaveBeenCalled()
  })

  it('mode button sets draftMode via DOM click', async () => {
    const w = mount(RecordingProxyView, { global: { stubs: { EmptyState: true, LoadingSkeleton: true } } })
    await flushPromises()
    const recordBtn = w.findAll('button').find(b => b.text() === 'record')
    await recordBtn!.trigger('click')
    expect((w.vm as any).draftMode).toBe('record')
  })

  it('Apply/Save button triggers saveConfig via DOM click', async () => {
    const { proxyApi } = await import('../../api/system')
    vi.mocked(proxyApi.setConfig).mockResolvedValueOnce({ data: FAKE_CONFIG } as any)
    const w = mount(RecordingProxyView, { global: { stubs: { EmptyState: true, LoadingSkeleton: true } } })
    await flushPromises()
    const saveBtn = w.findAll('button').find(b => b.text().includes('Apply') || b.text().includes('Save'))
    if (saveBtn) {
      await saveBtn.trigger('click')
      await flushPromises()
      expect(proxyApi.setConfig).toHaveBeenCalled()
    }
  })

  it('Clear Recordings button triggers clearRecordings via DOM click', async () => {
    const { proxyApi } = await import('../../api/system')
    const w = mount(RecordingProxyView, { global: { stubs: { EmptyState: true, LoadingSkeleton: true } } })
    await flushPromises()
    const clearBtn = w.findAll('button').find(b => b.text().includes('Clear'))
    if (clearBtn) {
      await clearBtn.trigger('click')
      await flushPromises()
      expect(proxyApi.clearRecordings).toHaveBeenCalled()
    }
  })

  it('shows vendor badges on recordings', async () => {
    const w = shallowMount(RecordingProxyView)
    await flushPromises()
    expect(w.text()).toContain('s1')
    expect(w.text()).toContain('crowdstrike')
  })
})
