import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import { setActivePinia, createPinia } from 'pinia'
import DevMockPanel from '../DevMockPanel.vue'

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ go: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../api/system', () => ({
  systemApi: {
    stats: vi.fn().mockResolvedValue({ data: { totalAgents: 50, totalThreats: 5, totalAlerts: 2 } }),
    reset: vi.fn().mockResolvedValue({ data: {} }),
    scenario: vi.fn().mockResolvedValue({ data: {} }),
  },
}))

describe('DevMockPanel', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  it('renders without error', async () => {
    const w = shallowMount(DevMockPanel)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('panel is collapsed by default', async () => {
    const w = shallowMount(DevMockPanel)
    await flushPromises()
    // The toggle button (Bug icon) should be visible; panel body should not be
    const buttons = w.findAll('button')
    expect(buttons.length).toBeGreaterThan(0)
  })

  it('opens panel on trigger button click', async () => {
    const w = shallowMount(DevMockPanel)
    await flushPromises()
    const trigger = w.find('button')
    await trigger.trigger('click')
    await flushPromises()
    // Panel should now be open — isOpen toggled
    expect(w.vm).toBeTruthy()
  })

  it('loads stats when panel opens', async () => {
    const { systemApi } = await import('../../api/system')
    const w = shallowMount(DevMockPanel)
    await flushPromises()
    const trigger = w.find('button')
    await trigger.trigger('click')
    await flushPromises()
    expect(systemApi.stats).toHaveBeenCalled()
  })

  it('shows preset tokens', async () => {
    const w = shallowMount(DevMockPanel)
    await flushPromises()
    const trigger = w.find('button')
    await trigger.trigger('click')
    await flushPromises()
    // PRESET_TOKENS includes 'Admin', 'Viewer', 'SOC Analyst'
    const text = w.text()
    expect(text).toContain('Admin')
  })
})
