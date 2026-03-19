import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/defender', () => ({
  ensureMdeAuth: vi.fn().mockResolvedValue(undefined),
  mdeAlertsApi: {
    list: vi.fn().mockResolvedValue({
      value: [
        {
          alertId: 'alert-1',
          title: 'Suspicious PowerShell Activity',
          severity: 'High',
          status: 'New',
          category: 'Execution',
          creationTime: '2025-01-10T08:00:00Z',
          machineId: 'machine-1',
          computerDnsName: 'WKSTN-001',
          detectionSource: 'WindowsDefenderAv',
        },
        {
          alertId: 'alert-2',
          title: 'Anomalous Network Traffic',
          severity: 'Medium',
          status: 'InProgress',
          category: 'CommandAndControl',
          creationTime: '2025-01-11T09:00:00Z',
          machineId: 'machine-2',
          computerDnsName: 'SRV-002',
          detectionSource: 'CustomTiIndicator',
        },
        {
          alertId: 'alert-3',
          title: 'Credential Dumping Attempt',
          severity: 'Low',
          status: 'Resolved',
          category: 'CredentialAccess',
          creationTime: '2025-01-12T10:00:00Z',
          machineId: 'machine-3',
          computerDnsName: 'SRV-003',
          detectionSource: 'AutomatedInvestigation',
        },
        {
          alertId: 'alert-4',
          title: 'Policy Violation Detected',
          severity: 'Informational',
          status: 'New',
          category: 'PolicyViolation',
          creationTime: '2025-01-13T11:00:00Z',
          machineId: 'machine-4',
          computerDnsName: null,
          detectionSource: 'MicrosoftDefenderForEndpoint',
        },
      ],
    }),
  },
}))

import MdeAlertsView from '@/views/mde/MdeAlertsView.vue'
import { ensureMdeAuth, mdeAlertsApi } from '@/api/defender'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/mde/alerts/:id', component: { template: '<div />' } },
  ],
})

const STUBS = {
  LoadingSkeleton: true,
  EmptyState: true,
  RouterLink: { template: '<a><slot /></a>' },
}

describe('MdeAlertsView', () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    await router.push('/')
    await router.isReady()
  })

  it('renders the page header with Alerts title', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Alerts')
  })

  it('calls ensureMdeAuth and mdeAlertsApi.list on mount', async () => {
    mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(ensureMdeAuth).toHaveBeenCalled()
    expect(mdeAlertsApi.list).toHaveBeenCalledWith(
      expect.objectContaining({ $top: 25, $skip: 0 })
    )
  })

  it('displays loaded alert titles', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Suspicious PowerShell Activity')
    expect(wrapper.text()).toContain('Anomalous Network Traffic')
  })

  it('sets loading to false after fetchAlerts completes', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('populates alerts from the response value array', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).alerts).toHaveLength(4)
  })

  it('falls back to empty array when response value is null', async () => {
    vi.mocked(mdeAlertsApi.list).mockResolvedValueOnce({ '@odata.context': '', value: null as unknown as import('../../../types/defender').MdeAlert[] })
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).alerts).toEqual([])
  })

  // fetchAlerts explicit calls with direction
  it('fetchAlerts with default direction resets skip to 0', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const vm = wrapper.vm as any
    await vm.fetchAlerts('next')
    expect(vm.skip).toBe(25)
    vi.mocked(mdeAlertsApi.list).mockClear()
    await vm.fetchAlerts()
    await flushPromises()
    expect(vm.skip).toBe(0)
    expect(mdeAlertsApi.list).toHaveBeenCalledWith(
      expect.objectContaining({ $skip: 0 })
    )
  })

  it('fetchAlerts with next increments skip by 25', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const vm = wrapper.vm as any
    expect(vm.skip).toBe(0)
    vi.mocked(mdeAlertsApi.list).mockClear()
    await vm.fetchAlerts('next')
    await flushPromises()
    expect(vm.skip).toBe(25)
    expect(mdeAlertsApi.list).toHaveBeenCalledWith(
      expect.objectContaining({ $skip: 25 })
    )
  })

  it('fetchAlerts with prev decrements skip by 25', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const vm = wrapper.vm as any
    await vm.fetchAlerts('next')
    expect(vm.skip).toBe(25)
    vi.mocked(mdeAlertsApi.list).mockClear()
    await vm.fetchAlerts('prev')
    await flushPromises()
    expect(vm.skip).toBe(0)
  })

  it('fetchAlerts with prev does not go below 0', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const vm = wrapper.vm as any
    expect(vm.skip).toBe(0)
    await vm.fetchAlerts('prev')
    expect(vm.skip).toBe(0)
  })

  it('fetchAlerts sets loading to false when API throws', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    vi.mocked(mdeAlertsApi.list).mockRejectedValueOnce(new Error('API error'))
    try {
      await (wrapper.vm as any).fetchAlerts()
    } catch {
      // expected
    }
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('fetchAlerts sends $filter when filterSeverity is set', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.filterSeverity = 'High'
    vi.mocked(mdeAlertsApi.list).mockClear()
    await vm.fetchAlerts()
    await flushPromises()
    expect(mdeAlertsApi.list).toHaveBeenCalledWith(
      expect.objectContaining({ $filter: expect.stringContaining("severity eq 'High'") })
    )
  })

  it('fetchAlerts sends $filter when filterStatus is set', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.filterStatus = 'New'
    vi.mocked(mdeAlertsApi.list).mockClear()
    await vm.fetchAlerts()
    await flushPromises()
    expect(mdeAlertsApi.list).toHaveBeenCalledWith(
      expect.objectContaining({ $filter: expect.stringContaining("status eq 'New'") })
    )
  })

  it('fetchAlerts combines multiple filters with and', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.filterSeverity = 'Medium'
    vm.filterStatus = 'InProgress'
    vi.mocked(mdeAlertsApi.list).mockClear()
    await vm.fetchAlerts()
    await flushPromises()
    const callArg = vi.mocked(mdeAlertsApi.list).mock.calls[0][0] as any
    expect(callArg.$filter).toContain("severity eq 'Medium'")
    expect(callArg.$filter).toContain("status eq 'InProgress'")
    expect(callArg.$filter).toContain(' and ')
  })

  it('fetchAlerts omits $filter when no filters are set', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    vi.mocked(mdeAlertsApi.list).mockClear()
    await (wrapper.vm as any).fetchAlerts()
    await flushPromises()
    const callArg = vi.mocked(mdeAlertsApi.list).mock.calls[0][0] as any
    expect(callArg.$filter).toBeUndefined()
  })

  // watch triggers
  it('watch on filterSeverity triggers fetchAlerts', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    vi.mocked(mdeAlertsApi.list).mockClear()
    ;(wrapper.vm as any).filterSeverity = 'Low'
    await flushPromises()
    expect(mdeAlertsApi.list).toHaveBeenCalled()
  })

  it('watch on filterStatus triggers fetchAlerts', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    vi.mocked(mdeAlertsApi.list).mockClear()
    ;(wrapper.vm as any).filterStatus = 'Resolved'
    await flushPromises()
    expect(mdeAlertsApi.list).toHaveBeenCalled()
  })

  // severityBadgeClass – all branches
  it('severityBadgeClass returns correct class for High', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('High')).toBe('bg-red-500/15 text-red-400')
  })

  it('severityBadgeClass returns correct class for Medium', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('Medium')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('severityBadgeClass returns correct class for Low', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('Low')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('severityBadgeClass returns correct class for Informational', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('Informational')).toBe('bg-gray-500/15 text-gray-400')
  })

  it('severityBadgeClass returns default class for unknown severity', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('Critical')).toBe('bg-gray-500/15 text-gray-400')
  })

  // statusBadgeClass – all branches
  it('statusBadgeClass returns correct class for New', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('New')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('statusBadgeClass returns correct class for InProgress', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('InProgress')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('statusBadgeClass returns correct class for Resolved', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('Resolved')).toBe('bg-green-500/15 text-green-400')
  })

  it('statusBadgeClass returns default class for unknown status', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('Unknown')).toBe('bg-gray-500/15 text-gray-400')
  })

  // hasPrev / hasNext computed properties
  it('hasPrev is false when skip is 0', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).hasPrev).toBe(false)
  })

  it('hasPrev is true when skip > 0', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    await (wrapper.vm as any).fetchAlerts('next')
    expect((wrapper.vm as any).hasPrev).toBe(true)
  })

  it('hasNext is false when fewer alerts than page size (25)', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    // 4 alerts < 25 → no next page
    expect((wrapper.vm as any).hasNext).toBe(false)
  })

  it('hasNext is true when alerts count equals page size (25)', async () => {
    const fullPage = Array.from({ length: 25 }, (_, i) => ({
      alertId: `alert-${i}`,
      title: `Alert ${i}`,
      severity: 'Low',
      status: 'New',
      category: 'Test',
      creationTime: '2025-01-01T00:00:00Z',
      machineId: `machine-${i}`,
      computerDnsName: `HOST-${i}`,
      detectionSource: 'Test',
      description: '',
      threatFamilyName: '',
      assignedTo: '',
      lastUpdateTime: '2025-01-01T00:00:00Z',
      resolvedTime: '',
      classification: '',
      determination: '',
    }))
    vi.mocked(mdeAlertsApi.list).mockResolvedValueOnce({ '@odata.context': '', value: fullPage })
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).hasNext).toBe(true)
  })

  // Empty state
  it('shows empty state when no alerts are returned', async () => {
    vi.mocked(mdeAlertsApi.list).mockResolvedValueOnce({ '@odata.context': '', value: [] })
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.html()).toContain('empty-state-stub')
  })

  // Refresh button
  it('Refresh button triggers fetchAlerts', async () => {
    const wrapper = mount(MdeAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    vi.mocked(mdeAlertsApi.list).mockClear()
    const refreshBtn = wrapper.findAll('button').find(b => b.text().includes('Refresh'))
    expect(refreshBtn).toBeDefined()
    await refreshBtn!.trigger('click')
    await flushPromises()
    expect(mdeAlertsApi.list).toHaveBeenCalled()
  })
})
