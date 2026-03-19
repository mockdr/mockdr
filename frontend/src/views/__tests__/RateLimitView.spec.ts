import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import RateLimitView from '@/views/RateLimitView.vue'

const mockGetRateLimit = vi.hoisted(() => vi.fn())
const mockSetRateLimit = vi.hoisted(() => vi.fn())

vi.mock('../../api/system', () => ({
  systemApi: {
    getRateLimit: mockGetRateLimit,
    setRateLimit: mockSetRateLimit,
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
    mockSetRateLimit.mockResolvedValue({ data: { enabled: false, requests_per_minute: 60, active_counters: 0 } })
  })

  it('renders the Rate-Limit heading', async () => {
    const w = mount(RateLimitView)
    await flushPromises()
    expect(w.text()).toContain('Rate-Limit Simulation')
  })

  it('calls getRateLimit on mount', async () => {
    mount(RateLimitView)
    await flushPromises()
    expect(mockGetRateLimit).toHaveBeenCalledOnce()
  })

  it('displays the current config values', async () => {
    const w = mount(RateLimitView)
    await flushPromises()
    expect(w.text()).toContain('ON')
    expect(w.text()).toContain('120')
    expect(w.text()).toContain('3')
  })

  it('shows RPM presets', async () => {
    const w = mount(RateLimitView)
    await flushPromises()
    expect(w.text()).toContain('60/min')
    expect(w.text()).toContain('300/min')
  })

  it('loading is false after fetchConfig completes', async () => {
    const w = mount(RateLimitView)
    await flushPromises()
    expect((w.vm as any).loading).toBe(false)
  })

  it('fetchConfig sets config from API response', async () => {
    const w = mount(RateLimitView)
    await flushPromises()
    expect((w.vm as any).config).toEqual(FAKE_CONFIG)
  })

  it('fetchConfig sets draftEnabled from API response', async () => {
    const w = mount(RateLimitView)
    await flushPromises()
    expect((w.vm as any).draftEnabled).toBe(true)
  })

  it('fetchConfig sets draftRpm from API response', async () => {
    const w = mount(RateLimitView)
    await flushPromises()
    expect((w.vm as any).draftRpm).toBe(120)
  })

  it('saveConfig calls systemApi.setRateLimit with draft values', async () => {
    const w = mount(RateLimitView)
    await flushPromises()
    ;(w.vm as any).draftEnabled = false
    ;(w.vm as any).draftRpm = 60
    await (w.vm as any).saveConfig()
    await flushPromises()
    expect(mockSetRateLimit).toHaveBeenCalledWith({ enabled: false, requests_per_minute: 60 })
  })

  it('saveConfig updates config from response', async () => {
    const w = mount(RateLimitView)
    await flushPromises()
    await (w.vm as any).saveConfig()
    await flushPromises()
    expect((w.vm as any).config.enabled).toBe(false)
    expect((w.vm as any).config.requests_per_minute).toBe(60)
  })

  it('saveConfig updates draftEnabled from response', async () => {
    const w = mount(RateLimitView)
    await flushPromises()
    await (w.vm as any).saveConfig()
    await flushPromises()
    expect((w.vm as any).draftEnabled).toBe(false)
  })

  it('saveConfig sets saving to false after completion', async () => {
    const w = mount(RateLimitView)
    await flushPromises()
    await (w.vm as any).saveConfig()
    await flushPromises()
    expect((w.vm as any).saving).toBe(false)
  })

  it('RPM_PRESETS contains standard presets', async () => {
    const w = mount(RateLimitView)
    expect((w.vm as any).RPM_PRESETS).toContain(60)
    expect((w.vm as any).RPM_PRESETS).toContain(120)
    expect((w.vm as any).RPM_PRESETS).toContain(300)
  })

  it('renders Apply Configuration button', async () => {
    const w = mount(RateLimitView)
    await flushPromises()
    expect(w.text()).toContain('Apply Configuration')
  })

  it('Refresh button triggers fetchConfig via DOM click', async () => {
    const w = mount(RateLimitView)
    await flushPromises()
    mockGetRateLimit.mockClear()
    const refreshBtn = w.findAll('button').find(b => b.text().includes('Refresh'))
    await refreshBtn!.trigger('click')
    await flushPromises()
    expect(mockGetRateLimit).toHaveBeenCalledOnce()
  })

  it('toggle button flips draftEnabled via DOM click', async () => {
    const w = mount(RateLimitView)
    await flushPromises()
    const initialEnabled = (w.vm as any).draftEnabled
    // The toggle button is a rounded-full button with no text
    const toggleBtn = w.find('button.rounded-full')
    await toggleBtn.trigger('click')
    expect((w.vm as any).draftEnabled).toBe(!initialEnabled)
  })

  it('preset RPM button sets draftRpm via DOM click', async () => {
    const w = mount(RateLimitView)
    await flushPromises()
    const presetBtn = w.findAll('button').find(b => b.text().includes('60/min'))
    await presetBtn!.trigger('click')
    expect((w.vm as any).draftRpm).toBe(60)
  })

  it('Apply Configuration button triggers saveConfig via DOM click', async () => {
    const w = mount(RateLimitView)
    await flushPromises()
    const applyBtn = w.findAll('button').find(b => b.text().includes('Apply Configuration'))
    await applyBtn!.trigger('click')
    await flushPromises()
    expect(mockSetRateLimit).toHaveBeenCalled()
  })
})
