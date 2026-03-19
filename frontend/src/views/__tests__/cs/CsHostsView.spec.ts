import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

const { mockQueryIds, mockGetEntities, mockAction } = vi.hoisted(() => {
  const mockQueryIds = vi.fn().mockResolvedValue({
    resources: ['host-id-1'],
    meta: { pagination: { total: 1 }, query_time: 0, powered_by: '', trace_id: '' },
    errors: [],
  })
  const mockGetEntities = vi.fn().mockResolvedValue({
    resources: [
      {
        device_id: 'host-id-1',
        hostname: 'WKSTN-001',
        status: 'normal',
        platform_name: 'Windows',
        os_version: 'Windows 11',
        external_ip: '203.0.113.1',
        local_ip: '10.0.0.1',
        mac_address: '00:11:22:33:44:55',
        agent_version: '7.0.0',
        product_type_desc: 'Workstation',
        first_seen: '2025-01-01T00:00:00Z',
        last_seen: '2025-06-01T12:00:00Z',
        groups: [],
        tags: [],
      },
    ],
    meta: { query_time: 0, powered_by: '', trace_id: '' },
    errors: [],
  })
  const mockAction = vi.fn().mockResolvedValue({ resources: [], errors: [] })
  return { mockQueryIds, mockGetEntities, mockAction }
})

vi.mock('../../../api/crowdstrike', () => ({
  ensureCsAuth: vi.fn().mockResolvedValue(undefined),
  csHostsApi: {
    queryIds: mockQueryIds,
    getEntities: mockGetEntities,
    action: mockAction,
  },
}))

vi.mock('../../../utils/formatters', () => ({
  relativeTime: vi.fn((v: string) => v ?? ''),
}))

import CsHostsView from '@/views/cs/CsHostsView.vue'
import { ensureCsAuth, csHostsApi } from '@/api/crowdstrike'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/crowdstrike/hosts/:id', component: { template: '<div />' } },
  ],
})

const stubs = { LoadingSkeleton: true, EmptyState: true }

const defaultHost = {
  device_id: 'host-id-1',
  hostname: 'WKSTN-001',
  status: 'normal',
  platform_name: 'Windows',
  os_version: 'Windows 11',
  external_ip: '203.0.113.1',
  local_ip: '10.0.0.1',
  mac_address: '00:11:22:33:44:55',
  agent_version: '7.0.0',
  product_type_desc: 'Workstation',
  first_seen: '2025-01-01T00:00:00Z',
  last_seen: '2025-06-01T12:00:00Z',
  groups: [],
  tags: [],
}

describe('CsHostsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQueryIds.mockResolvedValue({
      resources: ['host-id-1'],
      meta: { pagination: { total: 1 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    mockGetEntities.mockResolvedValue({
      resources: [defaultHost],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    mockAction.mockResolvedValue({ resources: [], errors: [] })
  })

  it('renders the page header', () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    expect(wrapper.text()).toContain('Hosts')
  })

  it('calls ensureCsAuth and csHostsApi.queryIds on mount', async () => {
    mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(ensureCsAuth).toHaveBeenCalled()
    expect(csHostsApi.queryIds).toHaveBeenCalledWith(expect.objectContaining({ offset: 0, limit: 25 }))
  })

  it('calls getEntities with resolved IDs', async () => {
    mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(csHostsApi.getEntities).toHaveBeenCalledWith(['host-id-1'])
  })

  it('renders host hostname after loading', async () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('WKSTN-001')
  })

  it('renders platform name in table', async () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('Windows')
  })

  it('renders host status', async () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('normal')
  })

  it('platformIcon returns W for Windows', () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).platformIcon('Windows')).toBe('W')
  })

  it('platformIcon returns M for Mac', () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).platformIcon('Mac')).toBe('M')
  })

  it('platformIcon returns L for Linux', () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).platformIcon('Linux')).toBe('L')
  })

  it('platformIcon returns ? for unknown platform', () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).platformIcon('ChromeOS')).toBe('?')
  })

  it('platformColor returns correct class for Windows', () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).platformColor('Windows')).toBe('bg-red-500/20 text-red-400')
  })

  it('platformColor returns correct class for Mac', () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).platformColor('Mac')).toBe('bg-orange-500/20 text-orange-400')
  })

  it('platformColor returns correct class for Linux', () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).platformColor('Linux')).toBe('bg-yellow-500/20 text-yellow-400')
  })

  it('platformColor returns default class for unknown platform', () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).platformColor('Other')).toBe('bg-gray-500/20 text-gray-400')
  })

  it('toggleSelect adds a host ID to selected set', async () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    expect(vm.selected.size).toBe(0)
    vm.toggleSelect('host-id-1')
    expect(vm.selected.has('host-id-1')).toBe(true)
  })

  it('toggleSelect removes a host ID when already selected', async () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.toggleSelect('host-id-1')
    expect(vm.selected.has('host-id-1')).toBe(true)
    vm.toggleSelect('host-id-1')
    expect(vm.selected.has('host-id-1')).toBe(false)
  })

  it('toggleAll selects all hosts when none are selected', async () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    expect(vm.allSelected).toBe(false)
    vm.toggleAll()
    expect(vm.selected.has('host-id-1')).toBe(true)
    expect(vm.allSelected).toBe(true)
  })

  it('toggleAll deselects all hosts when all are selected', async () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.toggleAll()
    expect(vm.allSelected).toBe(true)
    vm.toggleAll()
    expect(vm.selected.size).toBe(0)
    expect(vm.allSelected).toBe(false)
  })

  it('allSelected is false when hosts array is empty', async () => {
    mockQueryIds.mockResolvedValueOnce({
      resources: [],
      meta: { pagination: { total: 0 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).allSelected).toBe(false)
  })

  it('performAction does nothing when no hosts are selected', async () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    vi.clearAllMocks()
    await (wrapper.vm as any).performAction('contain')
    expect(csHostsApi.action).not.toHaveBeenCalled()
  })

  it('performAction calls csHostsApi.action with selected IDs and action name', async () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.toggleSelect('host-id-1')
    vi.clearAllMocks()
    await vm.performAction('contain')
    await flushPromises()
    expect(csHostsApi.action).toHaveBeenCalledWith('contain', ['host-id-1'])
  })

  it('performAction clears selection and re-fetches after success', async () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.toggleSelect('host-id-1')
    expect(vm.selected.size).toBe(1)
    await vm.performAction('lift_containment')
    await flushPromises()
    expect(vm.selected.size).toBe(0)
    expect(csHostsApi.queryIds).toHaveBeenCalledTimes(2)
  })

  it('fetchHosts(true) appends hosts to existing list', async () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    const initialCount = vm.hosts.length
    mockQueryIds.mockResolvedValueOnce({
      resources: ['host-id-2'],
      meta: { pagination: { total: 5 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    mockGetEntities.mockResolvedValueOnce({
      resources: [
        { device_id: 'host-id-2', hostname: 'WKSTN-002', status: 'normal', platform_name: 'Linux', groups: [], tags: [] },
      ],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    await vm.fetchHosts(true)
    await flushPromises()
    expect(vm.hosts.length).toBe(initialCount + 1)
  })

  it('hasMore is true when offset < total', async () => {
    mockQueryIds.mockResolvedValue({
      resources: ['host-id-1'],
      meta: { pagination: { total: 50 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).hasMore).toBe(true)
  })

  it('hasMore is false when offset equals total', async () => {
    mockQueryIds.mockResolvedValue({
      resources: ['host-id-1'],
      meta: { pagination: { total: 1 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).hasMore).toBe(false)
  })

  it('fetchHosts with append=false resets hosts when IDs are empty', async () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    expect(vm.hosts.length).toBe(1)
    mockQueryIds.mockResolvedValueOnce({
      resources: [],
      meta: { pagination: { total: 0 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    await vm.fetchHosts()
    await flushPromises()
    expect(vm.hosts.length).toBe(0)
  })

  it('fetchHosts builds filter param when filterPlatform is set', async () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.filterPlatform = 'Windows'
    vi.clearAllMocks()
    await vm.fetchHosts()
    await flushPromises()
    expect(csHostsApi.queryIds).toHaveBeenCalledWith(
      expect.objectContaining({ filter: "platform_name:'Windows'" }),
    )
  })

  it('fetchHosts builds combined filter when both filterPlatform and filterStatus are set', async () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.filterPlatform = 'Linux'
    vm.filterStatus = 'contained'
    vi.clearAllMocks()
    await vm.fetchHosts()
    await flushPromises()
    expect(csHostsApi.queryIds).toHaveBeenCalledWith(
      expect.objectContaining({ filter: "platform_name:'Linux'+status:'contained'" }),
    )
  })

  it('sets loading to false after fetch completes', async () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('Refresh button triggers fetchHosts via DOM click', async () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    vi.mocked(csHostsApi.queryIds).mockClear()
    const refreshBtn = wrapper.findAll('button').find(b => b.text().includes('Refresh'))
    await refreshBtn!.trigger('click')
    await flushPromises()
    expect(csHostsApi.queryIds).toHaveBeenCalled()
  })

  it('header checkbox triggers toggleAll via DOM change', async () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const headerCheckbox = wrapper.find('input[type="checkbox"]')
    await headerCheckbox.trigger('change')
    expect((wrapper.vm as any).selected.size).toBeGreaterThan(0)
  })

  it('row checkbox triggers toggleSelect via DOM change', async () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const checkboxes = wrapper.findAll('input[type="checkbox"]')
    if (checkboxes.length > 1) {
      await checkboxes[1].trigger('change')
      expect((wrapper.vm as any).selected.size).toBe(1)
    }
  })

  it('Contain button triggers performAction via DOM click', async () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.toggleSelect('host-id-1')
    await wrapper.vm.$nextTick()
    const containBtn = wrapper.findAll('button').find(b => b.text().includes('Contain') && !b.text().includes('Lift'))
    await containBtn!.trigger('click')
    await flushPromises()
    expect(csHostsApi.action).toHaveBeenCalledWith('contain', ['host-id-1'])
  })

  it('Lift Containment button triggers performAction via DOM click', async () => {
    const wrapper = mount(CsHostsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.toggleSelect('host-id-1')
    await wrapper.vm.$nextTick()
    const liftBtn = wrapper.findAll('button').find(b => b.text().includes('Lift'))
    await liftBtn!.trigger('click')
    await flushPromises()
    expect(csHostsApi.action).toHaveBeenCalledWith('lift_containment', ['host-id-1'])
  })
})
