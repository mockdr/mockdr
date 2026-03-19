import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/defender', () => ({
  ensureMdeAuth: vi.fn().mockResolvedValue(undefined),
  mdeMachinesApi: {
    get: vi.fn().mockResolvedValue({
      machineId: 'test-machine-id',
      computerDnsName: 'WKSTN-001',
      healthStatus: 'Active',
      osPlatform: 'Windows10',
      osVersion: '10.0.19041',
      riskScore: 'Medium',
      exposureLevel: 'Medium',
      lastIpAddress: '10.0.0.1',
      lastExternalIpAddress: '203.0.113.1',
      firstSeen: '2025-01-01T00:00:00Z',
      lastSeen: '2025-01-15T12:00:00Z',
      rbacGroupId: 0,
      rbacGroupName: 'Default',
      agentVersion: '10.3720',
      aadDeviceId: 'aad-device-123',
      isAadJoined: true,
      machineTags: ['prod', 'finance'],
    }),
    isolate: vi.fn().mockResolvedValue(undefined),
    unisolate: vi.fn().mockResolvedValue(undefined),
    scanAction: vi.fn().mockResolvedValue(undefined),
  },
  mdeAlertsApi: {
    list: vi.fn().mockResolvedValue({
      '@odata.context': 'https://api.securitycenter.microsoft.com/api/$metadata#Alerts',
      value: [
        {
          alertId: 'alert-1',
          title: 'Suspicious PowerShell',
          severity: 'High',
          status: 'New',
          category: 'Malware',
          machineId: 'test-machine-id',
          computerDnsName: 'WKSTN-001',
          description: '',
          detectionSource: '',
          threatFamilyName: '',
          assignedTo: '',
          creationTime: '',
          lastUpdateTime: '',
          resolvedTime: '',
          classification: '',
          determination: '',
        },
        {
          alertId: 'alert-2',
          title: 'Network Anomaly',
          severity: 'Medium',
          status: 'InProgress',
          category: 'SuspiciousActivity',
          machineId: 'test-machine-id',
          computerDnsName: 'WKSTN-001',
          description: '',
          detectionSource: '',
          threatFamilyName: '',
          assignedTo: '',
          creationTime: '',
          lastUpdateTime: '',
          resolvedTime: '',
          classification: '',
          determination: '',
        },
        {
          alertId: 'alert-3',
          title: 'Low Threat',
          severity: 'Low',
          status: 'Resolved',
          category: 'UnwantedSoftware',
          machineId: 'test-machine-id',
          computerDnsName: 'WKSTN-001',
          description: '',
          detectionSource: '',
          threatFamilyName: '',
          assignedTo: '',
          creationTime: '',
          lastUpdateTime: '',
          resolvedTime: '',
          classification: '',
          determination: '',
        },
      ],
    }),
  },
}))

import MdeMachineDetailView from '@/views/mde/MdeMachineDetailView.vue'
import { ensureMdeAuth, mdeMachinesApi, mdeAlertsApi } from '@/api/defender'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/mde/machines/:id', component: { template: '<div />' } },
    { path: '/defender/machines', component: { template: '<div />' } },
    { path: '/defender/machines/:id', component: { template: '<div />' } },
  ],
})

const STUBS = {
  LoadingSkeleton: true,
  EmptyState: true,
  StatusBadge: true,
  RouterLink: { template: '<a><slot /></a>' },
  Teleport: true,
}

describe('MdeMachineDetailView', () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    await router.push('/mde/machines/test-machine-id')
    await router.isReady()
  })

  it('renders machine detail with computer name', async () => {
    const wrapper = mount(MdeMachineDetailView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('WKSTN-001')
  })

  it('calls ensureMdeAuth, machines.get and alerts.list on mount', async () => {
    mount(MdeMachineDetailView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(ensureMdeAuth).toHaveBeenCalled()
    expect(mdeMachinesApi.get).toHaveBeenCalledWith('test-machine-id')
    expect(mdeAlertsApi.list).toHaveBeenCalledWith(
      expect.objectContaining({ $filter: expect.stringContaining('test-machine-id') })
    )
  })

  it('displays machine health status', async () => {
    const wrapper = mount(MdeMachineDetailView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Active')
  })

  it('displays machine OS platform', async () => {
    const wrapper = mount(MdeMachineDetailView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Windows10')
  })

  it('displays machine tags', async () => {
    const wrapper = mount(MdeMachineDetailView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('prod')
    expect(wrapper.text()).toContain('finance')
  })

  // healthBadgeClass - all branches
  it('healthBadgeClass returns correct class for Active', async () => {
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { healthBadgeClass: (s: string) => string }
    expect(vm.healthBadgeClass('Active')).toBe('bg-green-500/15 text-green-400')
  })

  it('healthBadgeClass returns correct class for Inactive', async () => {
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { healthBadgeClass: (s: string) => string }
    expect(vm.healthBadgeClass('Inactive')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('healthBadgeClass returns correct class for ImpairedCommunication', async () => {
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { healthBadgeClass: (s: string) => string }
    expect(vm.healthBadgeClass('ImpairedCommunication')).toBe('bg-red-500/15 text-red-400')
  })

  it('healthBadgeClass returns default for unknown status', async () => {
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { healthBadgeClass: (s: string) => string }
    expect(vm.healthBadgeClass('Unknown')).toBe('bg-gray-500/15 text-gray-400')
  })

  // severityBadgeClass - all branches
  it('severityBadgeClass returns correct class for High', async () => {
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { severityBadgeClass: (s: string) => string }
    expect(vm.severityBadgeClass('High')).toBe('bg-red-500/15 text-red-400')
  })

  it('severityBadgeClass returns correct class for Medium', async () => {
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { severityBadgeClass: (s: string) => string }
    expect(vm.severityBadgeClass('Medium')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('severityBadgeClass returns correct class for Low', async () => {
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { severityBadgeClass: (s: string) => string }
    expect(vm.severityBadgeClass('Low')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('severityBadgeClass returns default for unknown severity', async () => {
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { severityBadgeClass: (s: string) => string }
    expect(vm.severityBadgeClass('Unknown')).toBe('bg-gray-500/15 text-gray-400')
  })

  // performAction - isolate
  it('performAction isolate calls mdeMachinesApi.isolate and refreshes machine', async () => {
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(mdeMachinesApi.get).mockClear()
    const vm = wrapper.vm as unknown as { performAction: (action: 'isolate' | 'unisolate' | 'quickScan' | 'fullScan') => Promise<void> }
    await vm.performAction('isolate')
    await flushPromises()
    expect(mdeMachinesApi.isolate).toHaveBeenCalledWith('test-machine-id', 'Isolated from detail view')
    expect(mdeMachinesApi.get).toHaveBeenCalledWith('test-machine-id')
  })

  // performAction - unisolate
  it('performAction unisolate calls mdeMachinesApi.unisolate and refreshes machine', async () => {
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(mdeMachinesApi.get).mockClear()
    const vm = wrapper.vm as unknown as { performAction: (action: 'isolate' | 'unisolate' | 'quickScan' | 'fullScan') => Promise<void> }
    await vm.performAction('unisolate')
    await flushPromises()
    expect(mdeMachinesApi.unisolate).toHaveBeenCalledWith('test-machine-id', 'Released from detail view')
    expect(mdeMachinesApi.get).toHaveBeenCalledWith('test-machine-id')
  })

  // performAction - quickScan
  it('performAction quickScan calls mdeMachinesApi.scanAction with Quick', async () => {
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { performAction: (action: 'isolate' | 'unisolate' | 'quickScan' | 'fullScan') => Promise<void> }
    await vm.performAction('quickScan')
    await flushPromises()
    expect(mdeMachinesApi.scanAction).toHaveBeenCalledWith('test-machine-id', 'Quick')
  })

  // performAction - fullScan
  it('performAction fullScan calls mdeMachinesApi.scanAction with Full', async () => {
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { performAction: (action: 'isolate' | 'unisolate' | 'quickScan' | 'fullScan') => Promise<void> }
    await vm.performAction('fullScan')
    await flushPromises()
    expect(mdeMachinesApi.scanAction).toHaveBeenCalledWith('test-machine-id', 'Full')
  })

  // performAction does nothing when machine is null
  it('performAction does nothing when machine is null', async () => {
    vi.mocked(mdeMachinesApi.get).mockResolvedValueOnce(null as unknown as ReturnType<typeof mdeMachinesApi.get> extends Promise<infer T> ? T : never)
    vi.mocked(mdeAlertsApi.list).mockResolvedValueOnce({ '@odata.context': '', value: [] })
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(mdeMachinesApi.isolate).mockClear()
    const vm = wrapper.vm as unknown as { performAction: (action: 'isolate') => Promise<void> }
    await vm.performAction('isolate')
    await flushPromises()
    expect(mdeMachinesApi.isolate).not.toHaveBeenCalled()
  })

  // Tab switching
  it('can switch to alerts tab', async () => {
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { activeTab: string }
    vm.activeTab = 'alerts'
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Suspicious PowerShell')
    expect(wrapper.text()).toContain('Network Anomaly')
  })

  it('shows alert severity in alerts tab', async () => {
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { activeTab: string }
    vm.activeTab = 'alerts'
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('High')
    expect(wrapper.text()).toContain('Medium')
  })

  it('shows empty state when no alerts for machine', async () => {
    vi.mocked(mdeAlertsApi.list).mockResolvedValueOnce({ '@odata.context': '', value: [] })
    vi.mocked(mdeMachinesApi.get).mockResolvedValueOnce({
      machineId: 'test-machine-id',
      computerDnsName: 'WKSTN-001',
      healthStatus: 'Active',
      osPlatform: 'Windows10',
      osVersion: '10.0.19041',
      riskScore: 'Medium',
      exposureLevel: 'Medium',
      lastIpAddress: '10.0.0.1',
      lastExternalIpAddress: '203.0.113.1',
      firstSeen: '2025-01-01T00:00:00Z',
      lastSeen: '2025-01-15T12:00:00Z',
      rbacGroupId: 0,
      rbacGroupName: 'Default',
      agentVersion: '10.3720',
      aadDeviceId: 'aad-device-123',
      isAadJoined: true,
      machineTags: [],
    })
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { activeTab: string }
    vm.activeTab = 'alerts'
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('No alerts for this machine')
  })

  // actionLoading state
  it('sets actionLoading to false after performAction completes', async () => {
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      actionLoading: boolean
      performAction: (action: 'isolate') => Promise<void>
    }
    await vm.performAction('isolate')
    await flushPromises()
    expect(vm.actionLoading).toBe(false)
  })

  it('sets actionLoading to false even when performAction throws', async () => {
    vi.mocked(mdeMachinesApi.isolate).mockRejectedValueOnce(new Error('Isolate failed'))
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      actionLoading: boolean
      performAction: (action: 'isolate') => Promise<void>
    }
    try {
      await vm.performAction('isolate')
    } catch {
      // expected
    }
    await flushPromises()
    expect(vm.actionLoading).toBe(false)
  })

  // Error handling - machine not found shows appropriate state
  it('shows machine not found state when machine is null after load', async () => {
    vi.mocked(mdeMachinesApi.get).mockResolvedValueOnce(null as unknown as ReturnType<typeof mdeMachinesApi.get> extends Promise<infer T> ? T : never)
    vi.mocked(mdeAlertsApi.list).mockResolvedValueOnce({ '@odata.context': '', value: [] })
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('Machine not found')
  })

  // Error handling - loading set to false on error
  it('sets actionLoading to false when performAction action API throws', async () => {
    vi.mocked(mdeMachinesApi.scanAction).mockRejectedValueOnce(new Error('Scan failed'))
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      actionLoading: boolean
      performAction: (action: 'quickScan') => Promise<void>
    }
    try { await vm.performAction('quickScan') } catch { /* expected */ }
    await flushPromises()
    expect(vm.actionLoading).toBe(false)
  })

  it('Isolate button triggers performAction isolate via DOM click', async () => {
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(mdeMachinesApi.isolate).mockClear()
    const isolateBtn = wrapper.findAll('button').find(b => b.text().includes('Isolate'))
    await isolateBtn!.trigger('click')
    await flushPromises()
    expect(mdeMachinesApi.isolate).toHaveBeenCalled()
  })

  it('Release button triggers performAction unisolate via DOM click', async () => {
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(mdeMachinesApi.unisolate).mockClear()
    const releaseBtn = wrapper.findAll('button').find(b => b.text().includes('Release'))
    await releaseBtn!.trigger('click')
    await flushPromises()
    expect(mdeMachinesApi.unisolate).toHaveBeenCalled()
  })

  it('Quick Scan button triggers performAction quickScan via DOM click', async () => {
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(mdeMachinesApi.scanAction).mockClear()
    const scanBtn = wrapper.findAll('button').find(b => b.text().includes('Quick Scan'))
    await scanBtn!.trigger('click')
    await flushPromises()
    expect(mdeMachinesApi.scanAction).toHaveBeenCalledWith('test-machine-id', 'Quick')
  })

  it('Full Scan button triggers performAction fullScan via DOM click', async () => {
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(mdeMachinesApi.scanAction).mockClear()
    const scanBtn = wrapper.findAll('button').find(b => b.text().includes('Full Scan'))
    await scanBtn!.trigger('click')
    await flushPromises()
    expect(mdeMachinesApi.scanAction).toHaveBeenCalledWith('test-machine-id', 'Full')
  })

  it('tab button switches activeTab via DOM click', async () => {
    const wrapper = mount(MdeMachineDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const alertsTab = wrapper.findAll('button').find(b => b.text() === 'Alerts')
    await alertsTab!.trigger('click')
    expect((wrapper.vm as any).activeTab).toBe('alerts')
  })
})
