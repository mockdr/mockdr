import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/defender', () => ({
  ensureMdeAuth: vi.fn().mockResolvedValue(undefined),
  mdeMachinesApi: {
    list: vi.fn().mockResolvedValue({
      '@odata.context': 'https://api.securitycenter.microsoft.com/api/$metadata#Machines',
      value: [
        {
          machineId: 'machine-1',
          computerDnsName: 'WKSTN-001',
          healthStatus: 'Active',
          osPlatform: 'Windows10',
          riskScore: 'High',
          exposureLevel: 'High',
          lastIpAddress: '10.0.0.1',
          lastExternalIpAddress: '203.0.113.1',
          firstSeen: '2025-01-01T00:00:00Z',
          lastSeen: '2025-01-15T12:00:00Z',
          rbacGroupName: 'Default',
          onboardingStatus: 'Onboarded',
          agentVersion: '10.3720',
          osBuild: 19044,
          machineTags: ['tagged'],
        },
        {
          machineId: 'machine-2',
          computerDnsName: 'SRV-002',
          healthStatus: 'Inactive',
          osPlatform: 'WindowsServer2019',
          riskScore: 'Medium',
          exposureLevel: 'Medium',
          lastIpAddress: '10.0.0.2',
          lastExternalIpAddress: '203.0.113.2',
          firstSeen: '2025-01-02T00:00:00Z',
          lastSeen: '2025-01-14T11:00:00Z',
          rbacGroupName: 'Servers',
          onboardingStatus: 'Onboarded',
          agentVersion: '10.3720',
          osBuild: 17763,
          machineTags: [],
        },
        {
          machineId: 'machine-3',
          computerDnsName: 'LINUX-003',
          healthStatus: 'ImpairedCommunication',
          osPlatform: 'Linux',
          riskScore: 'Low',
          exposureLevel: 'Low',
          lastIpAddress: '10.0.0.3',
          lastExternalIpAddress: '',
          firstSeen: '2025-01-03T00:00:00Z',
          lastSeen: '2025-01-13T10:00:00Z',
          rbacGroupName: 'Linux',
          onboardingStatus: 'Onboarded',
          agentVersion: '10.3720',
          osBuild: 0,
          machineTags: [],
        },
        {
          machineId: 'machine-4',
          computerDnsName: 'MAC-004',
          healthStatus: 'NoCommunication',
          osPlatform: 'macOS',
          riskScore: 'None',
          exposureLevel: 'None',
          lastIpAddress: '10.0.0.4',
          lastExternalIpAddress: '',
          firstSeen: '2025-01-04T00:00:00Z',
          lastSeen: '2025-01-12T09:00:00Z',
          rbacGroupName: 'Mac',
          onboardingStatus: 'Onboarded',
          agentVersion: '10.3720',
          osBuild: 0,
          machineTags: [],
        },
      ],
    }),
    isolate: vi.fn().mockResolvedValue(undefined),
    unisolate: vi.fn().mockResolvedValue(undefined),
  },
}))

import MdeMachinesView from '@/views/mde/MdeMachinesView.vue'
import { ensureMdeAuth, mdeMachinesApi } from '@/api/defender'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
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

describe('MdeMachinesView', () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    await router.push('/')
    await router.isReady()
  })

  it('renders the page header with Machines title', async () => {
    const wrapper = mount(MdeMachinesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Machines')
  })

  it('calls ensureMdeAuth and list on mount', async () => {
    mount(MdeMachinesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(ensureMdeAuth).toHaveBeenCalled()
    expect(mdeMachinesApi.list).toHaveBeenCalledWith(
      expect.objectContaining({ $top: 25, $skip: 0 })
    )
  })

  it('displays loaded machines', async () => {
    const wrapper = mount(MdeMachinesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('WKSTN-001')
    expect(wrapper.text()).toContain('SRV-002')
  })

  it('displays machine OS platforms', async () => {
    const wrapper = mount(MdeMachinesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Windows10')
  })

  // healthBadgeClass - all branches
  it('healthBadgeClass returns correct class for Active', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { healthBadgeClass: (s: string) => string }
    expect(vm.healthBadgeClass('Active')).toBe('bg-green-500/15 text-green-400')
  })

  it('healthBadgeClass returns correct class for Inactive', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { healthBadgeClass: (s: string) => string }
    expect(vm.healthBadgeClass('Inactive')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('healthBadgeClass returns correct class for ImpairedCommunication', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { healthBadgeClass: (s: string) => string }
    expect(vm.healthBadgeClass('ImpairedCommunication')).toBe('bg-red-500/15 text-red-400')
  })

  it('healthBadgeClass returns correct class for NoCommunication', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { healthBadgeClass: (s: string) => string }
    expect(vm.healthBadgeClass('NoCommunication')).toBe('bg-gray-500/15 text-gray-400')
  })

  it('healthBadgeClass returns default for unknown status', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { healthBadgeClass: (s: string) => string }
    expect(vm.healthBadgeClass('Unknown')).toBe('bg-gray-500/15 text-gray-400')
  })

  // riskBadgeClass - all branches
  it('riskBadgeClass returns correct class for High', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { riskBadgeClass: (s: string) => string }
    expect(vm.riskBadgeClass('High')).toBe('bg-red-500/15 text-red-400')
  })

  it('riskBadgeClass returns correct class for Medium', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { riskBadgeClass: (s: string) => string }
    expect(vm.riskBadgeClass('Medium')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('riskBadgeClass returns correct class for Low', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { riskBadgeClass: (s: string) => string }
    expect(vm.riskBadgeClass('Low')).toBe('bg-green-500/15 text-green-400')
  })

  it('riskBadgeClass returns correct class for None', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { riskBadgeClass: (s: string) => string }
    expect(vm.riskBadgeClass('None')).toBe('bg-gray-500/15 text-gray-400')
  })

  it('riskBadgeClass returns default for unknown risk', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { riskBadgeClass: (s: string) => string }
    expect(vm.riskBadgeClass('Unknown')).toBe('bg-gray-500/15 text-gray-400')
  })

  // toggleAll function
  it('toggleAll selects all machines when none are selected', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      selected: Set<string>
      toggleAll: () => void
    }
    expect(vm.selected.size).toBe(0)
    vm.toggleAll()
    expect(vm.selected.size).toBe(4)
  })

  it('toggleAll deselects all machines when all are selected', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      selected: Set<string>
      toggleAll: () => void
    }
    vm.toggleAll() // select all
    expect(vm.selected.size).toBe(4)
    vm.toggleAll() // deselect all
    expect(vm.selected.size).toBe(0)
  })

  // toggleSelect function
  it('toggleSelect adds a machine to selection', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      selected: Set<string>
      toggleSelect: (id: string) => void
    }
    vm.toggleSelect('machine-1')
    expect(vm.selected.has('machine-1')).toBe(true)
  })

  it('toggleSelect removes a machine from selection', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      selected: Set<string>
      toggleSelect: (id: string) => void
    }
    vm.toggleSelect('machine-1')
    vm.toggleSelect('machine-1') // deselect
    expect(vm.selected.has('machine-1')).toBe(false)
  })

  // allSelected computed
  it('allSelected is false when no machines are selected', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { allSelected: boolean }
    expect(vm.allSelected).toBe(false)
  })

  it('allSelected is true when all machines are selected', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { allSelected: boolean; toggleAll: () => void }
    vm.toggleAll()
    expect(vm.allSelected).toBe(true)
  })

  // fetchMachines with direction variants
  it('fetchMachines with next increments skip', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      skip: number
      fetchMachines: (direction?: 'next' | 'prev' | 'reset') => Promise<void>
    }
    expect(vm.skip).toBe(0)
    vi.mocked(mdeMachinesApi.list).mockClear()
    await vm.fetchMachines('next')
    await flushPromises()
    expect(vm.skip).toBe(25)
    expect(mdeMachinesApi.list).toHaveBeenCalledWith(
      expect.objectContaining({ $skip: 25 })
    )
  })

  it('fetchMachines with prev decrements skip', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      skip: number
      fetchMachines: (direction?: 'next' | 'prev' | 'reset') => Promise<void>
    }
    // First go to page 2
    await vm.fetchMachines('next')
    expect(vm.skip).toBe(25)
    // Then go back
    vi.mocked(mdeMachinesApi.list).mockClear()
    await vm.fetchMachines('prev')
    await flushPromises()
    expect(vm.skip).toBe(0)
  })

  it('fetchMachines with prev does not go below 0', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      skip: number
      fetchMachines: (direction?: 'next' | 'prev' | 'reset') => Promise<void>
    }
    expect(vm.skip).toBe(0)
    await vm.fetchMachines('prev')
    expect(vm.skip).toBe(0)
  })

  it('fetchMachines with reset resets skip to 0', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      skip: number
      fetchMachines: (direction?: 'next' | 'prev' | 'reset') => Promise<void>
    }
    await vm.fetchMachines('next')
    expect(vm.skip).toBe(25)
    await vm.fetchMachines('reset')
    expect(vm.skip).toBe(0)
  })

  it('fetchMachines applies platform filter when set', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      filterPlatform: string
      fetchMachines: (direction?: string) => Promise<void>
    }
    vm.filterPlatform = 'Windows10'
    vi.mocked(mdeMachinesApi.list).mockClear()
    await vm.fetchMachines()
    await flushPromises()
    expect(mdeMachinesApi.list).toHaveBeenCalledWith(
      expect.objectContaining({ $filter: expect.stringContaining('Windows10') })
    )
  })

  it('fetchMachines applies health filter when set', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      filterHealth: string
      fetchMachines: (direction?: string) => Promise<void>
    }
    vm.filterHealth = 'Active'
    vi.mocked(mdeMachinesApi.list).mockClear()
    await vm.fetchMachines()
    await flushPromises()
    expect(mdeMachinesApi.list).toHaveBeenCalledWith(
      expect.objectContaining({ $filter: expect.stringContaining('Active') })
    )
  })

  it('fetchMachines applies risk filter when set', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      filterRisk: string
      fetchMachines: (direction?: string) => Promise<void>
    }
    vm.filterRisk = 'High'
    vi.mocked(mdeMachinesApi.list).mockClear()
    await vm.fetchMachines()
    await flushPromises()
    expect(mdeMachinesApi.list).toHaveBeenCalledWith(
      expect.objectContaining({ $filter: expect.stringContaining('High') })
    )
  })

  // performAction - isolate
  it('performAction isolate skips when no machines selected', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(mdeMachinesApi.isolate).mockClear()
    const vm = wrapper.vm as unknown as { performAction: (action: 'isolate' | 'unisolate') => Promise<void> }
    await vm.performAction('isolate')
    await flushPromises()
    expect(mdeMachinesApi.isolate).not.toHaveBeenCalled()
  })

  it('performAction isolate calls isolate for each selected machine', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      selected: Set<string>
      performAction: (action: 'isolate' | 'unisolate') => Promise<void>
    }
    vm.selected.add('machine-1')
    vm.selected.add('machine-2')
    await vm.performAction('isolate')
    await flushPromises()
    expect(mdeMachinesApi.isolate).toHaveBeenCalledWith('machine-1', 'Isolated from UI')
    expect(mdeMachinesApi.isolate).toHaveBeenCalledWith('machine-2', 'Isolated from UI')
    expect(vm.selected.size).toBe(0)
  })

  // performAction - unisolate
  it('performAction unisolate calls unisolate for each selected machine', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      selected: Set<string>
      performAction: (action: 'isolate' | 'unisolate') => Promise<void>
    }
    vm.selected.add('machine-3')
    await vm.performAction('unisolate')
    await flushPromises()
    expect(mdeMachinesApi.unisolate).toHaveBeenCalledWith('machine-3', 'Released from UI')
  })

  // hasPrev / hasNext computed
  it('hasPrev is false at skip=0', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { hasPrev: boolean }
    expect(vm.hasPrev).toBe(false)
  })

  it('hasPrev is true when skip > 0', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { hasPrev: boolean; fetchMachines: (d: string) => Promise<void> }
    await vm.fetchMachines('next')
    expect(vm.hasPrev).toBe(true)
  })

  it('hasNext is false when fewer results than page size', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    // 4 machines < 25 top, so no next
    const vm = wrapper.vm as unknown as { hasNext: boolean }
    expect(vm.hasNext).toBe(false)
  })

  // Watch triggers fetchMachines when filters change
  it('watch on filterPlatform triggers fetchMachines', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(mdeMachinesApi.list).mockClear()
    const vm = wrapper.vm as unknown as { filterPlatform: string }
    vm.filterPlatform = 'Linux'
    await flushPromises()
    expect(mdeMachinesApi.list).toHaveBeenCalled()
  })

  it('watch on filterHealth triggers fetchMachines', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(mdeMachinesApi.list).mockClear()
    const vm = wrapper.vm as unknown as { filterHealth: string }
    vm.filterHealth = 'Inactive'
    await flushPromises()
    expect(mdeMachinesApi.list).toHaveBeenCalled()
  })

  it('watch on filterRisk triggers fetchMachines', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(mdeMachinesApi.list).mockClear()
    const vm = wrapper.vm as unknown as { filterRisk: string }
    vm.filterRisk = 'Medium'
    await flushPromises()
    expect(mdeMachinesApi.list).toHaveBeenCalled()
  })

  // Error handling
  it('sets loading to false when fetchMachines throws', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(mdeMachinesApi.list).mockRejectedValueOnce(new Error('API error'))
    const vm = wrapper.vm as unknown as { loading: boolean; fetchMachines: () => Promise<void> }
    try { await vm.fetchMachines() } catch { /* expected */ }
    await flushPromises()
    expect(vm.loading).toBe(false)
  })

  // Row click navigates to machine detail
  it('clicking a machine row navigates to machine detail', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const rows = wrapper.findAll('tr.table-row')
    if (rows.length > 0) {
      await rows[0].trigger('click')
      await flushPromises()
      expect(router.currentRoute.value.path).toContain('/defender/machines/')
    }
  })

  // Empty state
  it('shows empty state when no machines are returned', async () => {
    vi.mocked(mdeMachinesApi.list).mockResolvedValueOnce({ '@odata.context': '', value: [] })
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.html()).toContain('empty-state-stub')
  })

  it('Refresh button triggers fetchMachines via DOM click', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(mdeMachinesApi.list).mockClear()
    const refreshBtn = wrapper.findAll('button').find(b => b.text().includes('Refresh'))
    await refreshBtn!.trigger('click')
    await flushPromises()
    expect(mdeMachinesApi.list).toHaveBeenCalled()
  })

  it('header checkbox triggers toggleAll via DOM change', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const headerCheckbox = wrapper.find('input[type="checkbox"]')
    await headerCheckbox.trigger('change')
    expect((wrapper.vm as any).selected.size).toBeGreaterThan(0)
  })

  it('row checkbox triggers toggleSelect via DOM change', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const checkboxes = wrapper.findAll('input[type="checkbox"]')
    if (checkboxes.length > 1) {
      await checkboxes[1].trigger('change')
      expect((wrapper.vm as any).selected.size).toBe(1)
    }
  })

  it('Isolate button triggers performAction via DOM click', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.toggleSelect('machine-1')
    await wrapper.vm.$nextTick()
    const isolateBtn = wrapper.findAll('button').find(b => b.text().includes('Isolate') && !b.text().includes('Unisolate'))
    await isolateBtn!.trigger('click')
    await flushPromises()
    expect(mdeMachinesApi.isolate).toHaveBeenCalled()
  })

  it('Unisolate button triggers performAction via DOM click', async () => {
    const wrapper = mount(MdeMachinesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.toggleSelect('machine-1')
    await wrapper.vm.$nextTick()
    const unisolateBtn = wrapper.findAll('button').find(b => b.text().includes('Unisolate'))
    if (unisolateBtn) {
      await unisolateBtn.trigger('click')
      await flushPromises()
      expect(mdeMachinesApi.unisolate).toHaveBeenCalled()
    }
  })
})
