import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/defender', () => ({
  ensureMdeAuth: vi.fn().mockResolvedValue(undefined),
  mdeIndicatorsApi: {
    list: vi.fn().mockResolvedValue({
      value: [
        {
          indicatorId: 'ind-1',
          indicatorValue: '1.2.3.4',
          indicatorType: 'IpAddress',
          action: 'AlertAndBlock',
          severity: 'High',
          title: 'Blocked IP',
          description: 'Known malicious IP',
          creationTimeDateTimeUtc: '2025-01-01T00:00:00Z',
        },
        {
          indicatorId: 'ind-2',
          indicatorValue: 'abc123sha256hash',
          indicatorType: 'FileSha256',
          action: 'Alert',
          severity: 'Medium',
          title: 'Suspicious File',
          description: 'Suspicious hash',
          creationTimeDateTimeUtc: '2025-01-02T00:00:00Z',
        },
        {
          indicatorId: 'ind-3',
          indicatorValue: 'goodapp.com',
          indicatorType: 'DomainName',
          action: 'Allowed',
          severity: 'Low',
          title: 'Allowed Domain',
          description: 'Trusted domain',
          creationTimeDateTimeUtc: '2025-01-03T00:00:00Z',
        },
        {
          indicatorId: 'ind-4',
          indicatorValue: 'info-indicator',
          indicatorType: 'Url',
          action: 'Alert',
          severity: 'Informational',
          title: 'Info Indicator',
          description: 'Informational',
          creationTimeDateTimeUtc: '2025-01-04T00:00:00Z',
        },
      ],
    }),
    create: vi.fn().mockResolvedValue({ indicatorId: 'ind-new' }),
    delete: vi.fn().mockResolvedValue(undefined),
  },
}))

import MdeIndicatorsView from '@/views/mde/MdeIndicatorsView.vue'
import { ensureMdeAuth, mdeIndicatorsApi } from '@/api/defender'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/mde/indicators/:id', component: { template: '<div />' } },
  ],
})

const STUBS = {
  LoadingSkeleton: true,
  EmptyState: true,
  StatusBadge: true,
  RouterLink: { template: '<a><slot /></a>' },
  Teleport: true,
}

describe('MdeIndicatorsView', () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    await router.push('/')
    await router.isReady()
  })

  it('renders the page header with Indicators title', async () => {
    const wrapper = mount(MdeIndicatorsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Indicators')
  })

  it('calls ensureMdeAuth and list on mount', async () => {
    mount(MdeIndicatorsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(ensureMdeAuth).toHaveBeenCalled()
    expect(mdeIndicatorsApi.list).toHaveBeenCalledWith({ $top: 100 })
  })

  it('displays loaded indicators', async () => {
    const wrapper = mount(MdeIndicatorsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('1.2.3.4')
    expect(wrapper.text()).toContain('abc123sha256hash')
    expect(wrapper.text()).toContain('Blocked IP')
  })

  it('displays indicator type and action', async () => {
    const wrapper = mount(MdeIndicatorsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('IpAddress')
    expect(wrapper.text()).toContain('AlertAndBlock')
  })

  // severityBadgeClass - all branches
  it('severityBadgeClass returns correct class for High', async () => {
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { severityBadgeClass: (s: string) => string }
    expect(vm.severityBadgeClass('High')).toBe('bg-red-500/15 text-red-400')
  })

  it('severityBadgeClass returns correct class for Medium', async () => {
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { severityBadgeClass: (s: string) => string }
    expect(vm.severityBadgeClass('Medium')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('severityBadgeClass returns correct class for Low', async () => {
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { severityBadgeClass: (s: string) => string }
    expect(vm.severityBadgeClass('Low')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('severityBadgeClass returns correct class for Informational', async () => {
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { severityBadgeClass: (s: string) => string }
    expect(vm.severityBadgeClass('Informational')).toBe('bg-gray-500/15 text-gray-400')
  })

  it('severityBadgeClass returns default class for unknown severity', async () => {
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { severityBadgeClass: (s: string) => string }
    expect(vm.severityBadgeClass('Unknown')).toBe('bg-gray-500/15 text-gray-400')
  })

  // actionBadgeClass - all branches
  it('actionBadgeClass returns correct class for AlertAndBlock', async () => {
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { actionBadgeClass: (a: string) => string }
    expect(vm.actionBadgeClass('AlertAndBlock')).toBe('bg-red-500/15 text-red-400')
  })

  it('actionBadgeClass returns correct class for Alert', async () => {
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { actionBadgeClass: (a: string) => string }
    expect(vm.actionBadgeClass('Alert')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('actionBadgeClass returns correct class for Allowed', async () => {
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { actionBadgeClass: (a: string) => string }
    expect(vm.actionBadgeClass('Allowed')).toBe('bg-green-500/15 text-green-400')
  })

  it('actionBadgeClass returns default class for unknown action', async () => {
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { actionBadgeClass: (a: string) => string }
    expect(vm.actionBadgeClass('Unknown')).toBe('bg-gray-500/15 text-gray-400')
  })

  // fetchIndicators explicit call
  it('fetchIndicators can be called explicitly', async () => {
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(mdeIndicatorsApi.list).mockClear()
    const vm = wrapper.vm as unknown as { fetchIndicators: () => Promise<void> }
    await vm.fetchIndicators()
    await flushPromises()
    expect(mdeIndicatorsApi.list).toHaveBeenCalledWith({ $top: 100 })
  })

  // createIndicator function
  it('createIndicator calls mdeIndicatorsApi.create and refreshes', async () => {
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      showCreateDialog: boolean
      newIndicator: {
        indicatorValue: string
        indicatorType: string
        action: string
        severity: string
        title: string
        description: string
      }
      createIndicator: () => Promise<void>
    }
    vm.showCreateDialog = true
    vm.newIndicator.indicatorValue = '10.20.30.40'
    vm.newIndicator.indicatorType = 'IpAddress'
    vm.newIndicator.action = 'AlertAndBlock'
    vm.newIndicator.severity = 'High'
    vm.newIndicator.title = 'Bad Actor IP'
    vm.newIndicator.description = 'Known C2 server'
    vi.mocked(mdeIndicatorsApi.list).mockClear()
    await vm.createIndicator()
    await flushPromises()
    expect(mdeIndicatorsApi.create).toHaveBeenCalledWith(
      expect.objectContaining({
        indicatorValue: '10.20.30.40',
        indicatorType: 'IpAddress',
        action: 'AlertAndBlock',
        severity: 'High',
        title: 'Bad Actor IP',
      })
    )
    expect(mdeIndicatorsApi.list).toHaveBeenCalled()
    expect(vm.showCreateDialog).toBe(false)
  })

  it('createIndicator resets the form after success', async () => {
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      newIndicator: { indicatorValue: string; title: string; indicatorType: string; action: string; severity: string; description: string }
      createIndicator: () => Promise<void>
    }
    vm.newIndicator.indicatorValue = '192.168.0.1'
    vm.newIndicator.title = 'Test'
    await vm.createIndicator()
    await flushPromises()
    expect(vm.newIndicator.indicatorValue).toBe('')
    expect(vm.newIndicator.title).toBe('')
    expect(vm.newIndicator.indicatorType).toBe('IpAddress')
    expect(vm.newIndicator.action).toBe('AlertAndBlock')
    expect(vm.newIndicator.severity).toBe('High')
  })

  // deleteIndicator function
  it('deleteIndicator calls mdeIndicatorsApi.delete and refreshes', async () => {
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { deleteIndicator: (id: string) => Promise<void> }
    vi.mocked(mdeIndicatorsApi.list).mockClear()
    await vm.deleteIndicator('ind-1')
    await flushPromises()
    expect(mdeIndicatorsApi.delete).toHaveBeenCalledWith('ind-1')
    expect(mdeIndicatorsApi.list).toHaveBeenCalled()
  })

  // Error handling
  it('sets loading to false when fetchIndicators throws', async () => {
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(mdeIndicatorsApi.list).mockRejectedValueOnce(new Error('API error'))
    const vm = wrapper.vm as unknown as { loading: boolean; fetchIndicators: () => Promise<void> }
    try { await vm.fetchIndicators() } catch { /* expected */ }
    await flushPromises()
    expect(vm.loading).toBe(false)
  })

  it('sets loading to false when createIndicator throws', async () => {
    vi.mocked(mdeIndicatorsApi.create).mockRejectedValueOnce(new Error('Create failed'))
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      loading: boolean
      newIndicator: { indicatorValue: string; title: string }
      createIndicator: () => Promise<void>
    }
    vm.newIndicator.indicatorValue = '1.1.1.1'
    vm.newIndicator.title = 'Test'
    try {
      await vm.createIndicator()
    } catch {
      // expected
    }
    await flushPromises()
    expect(vm.loading).toBe(false)
  })

  it('sets loading to false when deleteIndicator throws', async () => {
    vi.mocked(mdeIndicatorsApi.delete).mockRejectedValueOnce(new Error('Delete failed'))
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { loading: boolean; deleteIndicator: (id: string) => Promise<void> }
    try {
      await vm.deleteIndicator('ind-1')
    } catch {
      // expected
    }
    await flushPromises()
    expect(vm.loading).toBe(false)
  })

  // Empty state
  it('shows empty state when no indicators are returned', async () => {
    vi.mocked(mdeIndicatorsApi.list).mockResolvedValueOnce({ '@odata.context': '', value: [] })
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.html()).toContain('empty-state-stub')
  })

  // Open create dialog
  it('opens create dialog when Create button is clicked', async () => {
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const btn = wrapper.findAll('button').find(b => b.text().includes('Create'))
    expect(btn).toBeDefined()
    await btn!.trigger('click')
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Create Indicator')
  })

  it('Refresh button calls fetchIndicators via DOM click', async () => {
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(mdeIndicatorsApi.list).mockClear()
    const btn = wrapper.findAll('button').find(b => b.text().includes('Refresh'))
    await btn!.trigger('click')
    await flushPromises()
    expect(mdeIndicatorsApi.list).toHaveBeenCalled()
  })

  it('Create button in dialog calls createIndicator via DOM click', async () => {
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { showCreateDialog: boolean; newIndicator: { indicatorValue: string; title: string } }
    vm.showCreateDialog = true
    vm.newIndicator.indicatorValue = '5.5.5.5'
    vm.newIndicator.title = 'Test'
    await wrapper.vm.$nextTick()
    // The dialog's Create button has class "btn-ghost text-green-400 text-sm"
    const createBtn = wrapper.find('button.btn-ghost.text-green-400.text-sm')
    await createBtn.trigger('click')
    await flushPromises()
    expect(mdeIndicatorsApi.create).toHaveBeenCalled()
  })

  it('Cancel button in dialog closes it via DOM click', async () => {
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { showCreateDialog: boolean }
    vm.showCreateDialog = true
    await wrapper.vm.$nextTick()
    const cancelBtn = wrapper.findAll('button').find(b => b.text() === 'Cancel')
    await cancelBtn!.trigger('click')
    expect(vm.showCreateDialog).toBe(false)
  })

  it('delete button in table calls deleteIndicator via DOM click', async () => {
    const wrapper = mount(MdeIndicatorsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(mdeIndicatorsApi.list).mockClear()
    const deleteBtn = wrapper.find('button.btn-ghost.text-red-400')
    await deleteBtn.trigger('click')
    await flushPromises()
    expect(mdeIndicatorsApi.delete).toHaveBeenCalledWith('ind-1')
  })
})
