import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { setActivePinia, createPinia } from 'pinia'
import DevMockPanel from '@/components/DevMockPanel.vue'

const mockRouterGo = vi.hoisted(() => vi.fn())

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ go: mockRouterGo })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../api/system', () => ({
  systemApi: {
    stats: vi.fn().mockResolvedValue({ data: { totalAgents: 50, totalThreats: 5, totalAlerts: 2 } }),
    reset: vi.fn().mockResolvedValue({ data: {} }),
    scenario: vi.fn().mockResolvedValue({ data: {} }),
  },
}))

vi.mock('../../stores/auth', () => ({
  useAuthStore: vi.fn(() => ({
    login: vi.fn().mockResolvedValue(undefined),
    token: 'test-token',
  })),
  PRESET_TOKENS: [
    { label: 'Admin', token: 'admin-token' },
    { label: 'Viewer', token: 'viewer-token' },
    { label: 'SOC Analyst', token: 'soc-token' },
  ],
}))

describe('DevMockPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    setActivePinia(createPinia())
    vi.stubGlobal('navigator', {
      clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
    })
  })

  it('renders without error', async () => {
    const w = mount(DevMockPanel)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('panel is closed by default', () => {
    const w = mount(DevMockPanel)
    expect((w.vm as any).isOpen).toBe(false)
  })

  it('onOpen sets isOpen to true and calls loadStats', async () => {
    const { systemApi } = await import('../../api/system')
    const w = mount(DevMockPanel)
    ;(w.vm as any).onOpen()
    await flushPromises()
    expect((w.vm as any).isOpen).toBe(true)
    expect(systemApi.stats).toHaveBeenCalled()
  })

  it('loadStats fetches stats from systemApi', async () => {
    const { systemApi } = await import('../../api/system')
    const w = mount(DevMockPanel)
    await (w.vm as any).loadStats()
    await flushPromises()
    expect(systemApi.stats).toHaveBeenCalled()
    expect((w.vm as any).stats).toEqual({ totalAgents: 50, totalThreats: 5, totalAlerts: 2 })
  })

  it('loadStats handles errors silently', async () => {
    const { systemApi } = await import('../../api/system')
    vi.mocked(systemApi.stats).mockRejectedValueOnce(new Error('Server down'))
    const w = mount(DevMockPanel)
    await expect((w.vm as any).loadStats()).resolves.toBeUndefined()
  })

  it('triggerScenario calls systemApi.scenario and reloads', async () => {
    const { systemApi } = await import('../../api/system')
    const w = mount(DevMockPanel)
    await (w.vm as any).triggerScenario('mass_infection')
    await flushPromises()
    expect(systemApi.scenario).toHaveBeenCalledWith('mass_infection')
    expect(mockRouterGo).toHaveBeenCalledWith(0)
  })

  it('triggerScenario sets loading to false after completion', async () => {
    const w = mount(DevMockPanel)
    await (w.vm as any).triggerScenario('apt_campaign')
    await flushPromises()
    expect((w.vm as any).loading).toBe(false)
  })

  it('resetAll calls systemApi.reset and reloads', async () => {
    const { systemApi } = await import('../../api/system')
    const w = mount(DevMockPanel)
    await (w.vm as any).resetAll()
    await flushPromises()
    expect(systemApi.reset).toHaveBeenCalled()
    expect(mockRouterGo).toHaveBeenCalledWith(0)
  })

  it('resetAll sets loading to false after completion', async () => {
    const w = mount(DevMockPanel)
    await (w.vm as any).resetAll()
    await flushPromises()
    expect((w.vm as any).loading).toBe(false)
  })

  it('switchToken calls auth.login and reloads', async () => {
    const mockLogin = vi.fn().mockResolvedValue(undefined)
    const { useAuthStore } = await import('../../stores/auth')
    vi.mocked(useAuthStore).mockReturnValueOnce({ login: mockLogin, token: 'old-token' } as any)
    const w = mount(DevMockPanel)
    await (w.vm as any).switchToken('new-token')
    await flushPromises()
    expect(mockLogin).toHaveBeenCalledWith('new-token')
    expect(mockRouterGo).toHaveBeenCalledWith(0)
  })

  it('copyToken writes to clipboard', async () => {
    const w = mount(DevMockPanel)
    ;(w.vm as any).copyToken('admin-token')
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('admin-token')
  })

  it('copyToken sets copiedToken then clears it after timeout', async () => {
    vi.useFakeTimers()
    const w = mount(DevMockPanel)
    ;(w.vm as any).copyToken('viewer-token')
    expect((w.vm as any).copiedToken).toBe('viewer-token')
    vi.advanceTimersByTime(2100)
    expect((w.vm as any).copiedToken).toBeNull()
    vi.useRealTimers()
  })

  it('opens panel on trigger button click and loads stats', async () => {
    const { systemApi } = await import('../../api/system')
    vi.mocked(systemApi.stats).mockClear()
    const w = mount(DevMockPanel)
    const trigger = w.find('button')
    await trigger.trigger('click')
    await flushPromises()
    expect((w.vm as any).isOpen).toBe(true)
    expect(systemApi.stats).toHaveBeenCalled()
  })
})
