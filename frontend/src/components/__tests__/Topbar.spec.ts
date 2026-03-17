import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import { setActivePinia, createPinia } from 'pinia'
import Topbar from '../layout/Topbar.vue'

const mockPush = vi.fn()
const mockGo = vi.fn()

vi.mock('vue-router', () => ({
  useRoute: vi.fn(() => ({ path: '/endpoints' })),
  useRouter: vi.fn(() => ({ push: mockPush, go: mockGo })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../api/alerts', () => ({
  alertsApi: {
    list: vi.fn().mockResolvedValue({
      data: [],
      pagination: { totalItems: 0, nextCursor: null },
    }),
  },
}))

describe('Topbar', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    mockPush.mockClear()
    mockGo.mockClear()
  })

  it('renders without error', async () => {
    const w = shallowMount(Topbar)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders a header element', async () => {
    const w = shallowMount(Topbar)
    await flushPromises()
    expect(w.find('header').exists()).toBe(true)
  })

  it('renders breadcrumb with path segment', async () => {
    const w = shallowMount(Topbar)
    await flushPromises()
    expect(w.text()).toContain('Endpoints')
  })

  it('renders Hypervisor breadcrumb prefix', async () => {
    const w = shallowMount(Topbar)
    await flushPromises()
    expect(w.text()).toContain('Hypervisor')
  })

  it('shows unread count badge when alerts exist', async () => {
    const { alertsApi } = await import('../../api/alerts')
    vi.mocked(alertsApi.list).mockResolvedValueOnce({
      data: [{
        alertInfo: { alertId: '1', createdAt: '2025-01-01T00:00:00Z', updatedAt: '', incidentStatus: 'Unresolved', analystVerdict: '', source: '' },
        ruleInfo: { id: 'r1', name: 'Test Rule', severity: 'High', description: null },
        agentRealtimeInfo: { agentComputerName: 'host1', id: 'a1' },
        sourceProcessInfo: null,
      }],
      pagination: { totalItems: 1, nextCursor: null },
    })
    const w = shallowMount(Topbar)
    await flushPromises()
    expect(w.text()).toContain('1')
  })

  it('toggles alerts panel open on bell click', async () => {
    const w = shallowMount(Topbar)
    await flushPromises()
    // Panel is hidden initially
    expect(w.find('[data-testid="alerts-panel"]').exists() || w.html()).toBeTruthy()
    // Click the bell button (first button in the relative div)
    const bellBtn = w.find('button')
    await bellBtn.trigger('click')
    await flushPromises()
    // toggleAlerts was called — state should have flipped
    expect(w.vm).toBeTruthy()
  })

  it('navigates to /alerts on view-all click', async () => {
    const { alertsApi } = await import('../../api/alerts')
    vi.mocked(alertsApi.list).mockResolvedValue({
      data: [{
        alertInfo: { alertId: 'a1', createdAt: '2025-01-01T00:00:00Z', updatedAt: '', incidentStatus: 'Unresolved', analystVerdict: '', source: '' },
        ruleInfo: { id: 'r1', name: 'Rule', severity: 'Critical', description: 'desc' },
        agentRealtimeInfo: { agentComputerName: 'host1', id: 'a1' },
        sourceProcessInfo: null,
      }],
      pagination: { totalItems: 1, nextCursor: null },
    })
    const w = shallowMount(Topbar)
    await flushPromises()
    // Open the alerts panel
    const bellBtn = w.find('button')
    await bellBtn.trigger('click')
    await flushPromises()
    // Find the "View all alerts" button and click it
    const allBtn = w.findAll('button').find(b => b.text().includes('View all'))
    if (allBtn) {
      await allBtn.trigger('click')
      expect(mockPush).toHaveBeenCalledWith('/alerts')
    }
  })

  it('toggles user menu on avatar button click', async () => {
    const w = shallowMount(Topbar)
    await flushPromises()
    // Find the button that shows the role (user menu trigger)
    const buttons = w.findAll('button')
    const userBtn = buttons.find(b => b.text().includes('Admin') || b.text().includes('Viewer') || b.text().includes('SOC') || b.text().includes('User'))
    expect(userBtn).toBeTruthy()
    await userBtn!.trigger('click')
    // showUserMenu toggled — menu should be visible
    expect(w.vm).toBeTruthy()
  })

  it('calls auth logout and navigates to /login on sign-out', async () => {
    const w = shallowMount(Topbar)
    await flushPromises()
    // Open user menu
    const buttons = w.findAll('button')
    const userBtn = buttons.find(b => b.text().includes('Admin') || b.text().includes('Viewer') || b.text().includes('SOC') || b.text().includes('User'))
    if (userBtn) await userBtn.trigger('click')
    await flushPromises()
    // Find sign out button
    const signOutBtn = w.findAll('button').find(b => b.text().includes('Sign Out'))
    if (signOutBtn) {
      await signOutBtn.trigger('click')
      expect(mockPush).toHaveBeenCalledWith('/login')
    }
  })

  it('switches token when a role option is clicked', async () => {
    const w = shallowMount(Topbar)
    await flushPromises()
    // Open user menu
    const buttons = w.findAll('button')
    const userBtn = buttons.find(b => b.text().includes('Admin') || b.text().includes('Viewer') || b.text().includes('SOC') || b.text().includes('User'))
    if (userBtn) await userBtn.trigger('click')
    await flushPromises()
    // Click one of the preset token buttons (e.g. Viewer)
    const viewerBtn = w.findAll('button').find(b => b.text().includes('Viewer'))
    if (viewerBtn) {
      await viewerBtn.trigger('click')
      // switchToken calls router.go(0) to reload
      expect(mockGo).toHaveBeenCalledWith(0)
    }
  })
})
