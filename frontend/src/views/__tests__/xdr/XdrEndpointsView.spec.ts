import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/cortex', () => ({
  xdrEndpointsApi: {
    list: vi.fn().mockResolvedValue({
      reply: {
        total_count: 3,
        result_count: 3,
        endpoints: [
          {
            endpoint_id: 'ep-001',
            endpoint_name: 'WKSTN-001',
            endpoint_status: 'connected',
            os_type: 'windows',
            ip: ['10.0.0.1'],
            domain: 'corp.local',
            last_seen: 1700000000000,
            is_isolated: 'unisolated',
            users: ['alice'],
            alias: '',
            content_version: '1.0',
            install_date: '2025-01-01',
            endpoint_version: '7.0.0',
          },
          {
            endpoint_id: 'ep-002',
            endpoint_name: 'SRV-001',
            endpoint_status: 'disconnected',
            os_type: 'linux',
            ip: '192.168.1.10',
            domain: 'corp.local',
            last_seen: 1699000000000,
            is_isolated: 'isolated',
            users: ['root'],
            alias: '',
            content_version: '1.0',
            install_date: '2025-01-01',
            endpoint_version: '7.0.0',
          },
          {
            endpoint_id: 'ep-003',
            endpoint_name: 'MAC-001',
            endpoint_status: 'lost',
            os_type: 'macos',
            ip: [],
            domain: '',
            last_seen: 0,
            is_isolated: 'not_isolated',
            users: [],
            alias: '',
            content_version: '1.0',
            install_date: '2025-01-01',
            endpoint_version: '7.0.0',
          },
        ],
      },
    }),
    isolate: vi.fn().mockResolvedValue({ reply: { action_id: 'act-001' } }),
    unisolate: vi.fn().mockResolvedValue({ reply: { action_id: 'act-002' } }),
  },
}))

import XdrEndpointsView from '@/views/xdr/XdrEndpointsView.vue'

const STUBS = {
  LoadingSkeleton: true,
  EmptyState: true,
  StatusBadge: true,
  RouterLink: { template: '<a><slot /></a>' },
  Teleport: true,
}

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/cortex-xdr/endpoints/:id', component: { template: '<div />' } },
  ],
})

function mountView() {
  return mount(XdrEndpointsView, {
    global: { plugins: [router], stubs: STUBS },
  })
}

describe('XdrEndpointsView', () => {
  beforeEach(async () => {
    await router.push('/')
    await router.isReady()
    vi.clearAllMocks()
  })

  it('renders the page header', () => {
    const wrapper = mountView()
    expect(wrapper.text()).toContain('XDR')
    expect(wrapper.text()).toContain('Endpoints')
  })

  it('fetches and displays endpoints on mount', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('WKSTN-001')
    expect(wrapper.text()).toContain('SRV-001')
    expect(wrapper.text()).toContain('MAC-001')
  })

  it('calls fetchEndpoints via wrapper.vm', async () => {
    const { xdrEndpointsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    await (wrapper.vm as any).fetchEndpoints()
    expect(xdrEndpointsApi.list).toHaveBeenCalledTimes(2)
  })

  it('calls fetchEndpoints when Refresh button is clicked', async () => {
    const { xdrEndpointsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const refreshBtn = wrapper.find('button')
    await refreshBtn.trigger('click')
    await flushPromises()
    expect(xdrEndpointsApi.list).toHaveBeenCalledTimes(2)
  })

  it('statusBadgeClass returns correct class for connected', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('connected')).toBe('bg-green-500/15 text-green-400')
  })

  it('statusBadgeClass returns correct class for disconnected', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('disconnected')).toBe('bg-red-500/15 text-red-400')
  })

  it('statusBadgeClass returns correct class for lost', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('lost')).toBe('bg-gray-500/15 text-gray-400')
  })

  it('statusBadgeClass returns default class for unknown', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('unknown')).toBe('bg-gray-500/15 text-gray-400')
  })

  it('statusBadgeClass handles null input', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass(null)).toBe('bg-gray-500/15 text-gray-400')
  })

  it('isolationBadgeClass returns correct class for isolated', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).isolationBadgeClass('isolated')).toBe('bg-red-500/15 text-red-400')
  })

  it('isolationBadgeClass returns correct class for unisolated', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).isolationBadgeClass('unisolated')).toBe('bg-green-500/15 text-green-400')
  })

  it('isolationBadgeClass returns correct class for not_isolated', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).isolationBadgeClass('not_isolated')).toBe('bg-green-500/15 text-green-400')
  })

  it('isolationBadgeClass returns default class for unknown', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).isolationBadgeClass('unknown')).toBe('bg-gray-500/15 text-gray-400')
  })

  it('isolationBadgeClass handles null input', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).isolationBadgeClass(null)).toBe('bg-gray-500/15 text-gray-400')
  })

  it('relativeTime returns -- for falsy epoch', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).relativeTime(0)).toBe('--')
  })

  it('relativeTime returns seconds ago for recent timestamp', async () => {
    const wrapper = mountView()
    await flushPromises()
    const now = Date.now()
    const result = (wrapper.vm as any).relativeTime(now - 30000)
    expect(result).toMatch(/s ago/)
  })

  it('relativeTime returns minutes ago', async () => {
    const wrapper = mountView()
    await flushPromises()
    const now = Date.now()
    const result = (wrapper.vm as any).relativeTime(now - 5 * 60 * 1000)
    expect(result).toMatch(/m ago/)
  })

  it('relativeTime returns hours ago', async () => {
    const wrapper = mountView()
    await flushPromises()
    const now = Date.now()
    const result = (wrapper.vm as any).relativeTime(now - 2 * 3600 * 1000)
    expect(result).toMatch(/h ago/)
  })

  it('relativeTime returns days ago', async () => {
    const wrapper = mountView()
    await flushPromises()
    const now = Date.now()
    const result = (wrapper.vm as any).relativeTime(now - 3 * 86400 * 1000)
    expect(result).toMatch(/d ago/)
  })

  it('toggleSelect adds endpoint to selected set', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.toggleSelect('ep-001')
    expect(vm.selected.has('ep-001')).toBe(true)
  })

  it('toggleSelect removes endpoint when already selected', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.toggleSelect('ep-001')
    vm.toggleSelect('ep-001')
    expect(vm.selected.has('ep-001')).toBe(false)
  })

  it('toggleAll selects all filtered endpoints when none selected', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.toggleAll()
    expect(vm.selected.size).toBe(3)
  })

  it('toggleAll deselects all when all are already selected', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.toggleAll()
    vm.toggleAll()
    expect(vm.selected.size).toBe(0)
  })

  it('allSelected computed is true when all filtered endpoints selected', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.toggleAll()
    await wrapper.vm.$nextTick()
    expect(vm.allSelected).toBe(true)
  })

  it('allSelected computed is false when some are not selected', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.toggleSelect('ep-001')
    await wrapper.vm.$nextTick()
    expect(vm.allSelected).toBe(false)
  })

  it('filterOs filters endpoints by OS type', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.filterOs = 'windows'
    await wrapper.vm.$nextTick()
    expect(vm.filteredEndpoints.length).toBe(1)
    expect(vm.filteredEndpoints[0].endpoint_id).toBe('ep-001')
  })

  it('filterStatus filters endpoints by status', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.filterStatus = 'disconnected'
    await wrapper.vm.$nextTick()
    expect(vm.filteredEndpoints.length).toBe(1)
    expect(vm.filteredEndpoints[0].endpoint_id).toBe('ep-002')
  })

  it('combining filterOs and filterStatus narrows results', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.filterOs = 'linux'
    vm.filterStatus = 'disconnected'
    await wrapper.vm.$nextTick()
    expect(vm.filteredEndpoints.length).toBe(1)
    expect(vm.filteredEndpoints[0].endpoint_id).toBe('ep-002')
  })

  it('performAction isolate calls xdrEndpointsApi.isolate for each selected endpoint', async () => {
    const { xdrEndpointsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.toggleSelect('ep-001')
    vm.toggleSelect('ep-002')
    await vm.performAction('isolate')
    await flushPromises()
    expect(xdrEndpointsApi.isolate).toHaveBeenCalledWith('ep-001')
    expect(xdrEndpointsApi.isolate).toHaveBeenCalledWith('ep-002')
  })

  it('performAction unisolate calls xdrEndpointsApi.unisolate for each selected endpoint', async () => {
    const { xdrEndpointsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.toggleSelect('ep-001')
    await vm.performAction('unisolate')
    await flushPromises()
    expect(xdrEndpointsApi.unisolate).toHaveBeenCalledWith('ep-001')
  })

  it('performAction with no selection does nothing', async () => {
    const { xdrEndpointsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    await (wrapper.vm as any).performAction('isolate')
    await flushPromises()
    expect(xdrEndpointsApi.isolate).not.toHaveBeenCalled()
  })

  it('performAction clears selection after completing', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.toggleSelect('ep-001')
    expect(vm.selected.size).toBe(1)
    await vm.performAction('isolate')
    await flushPromises()
    expect(vm.selected.size).toBe(0)
  })

  it('shows IP address for array IP', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('10.0.0.1')
  })

  it('shows IP address for string IP', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('192.168.1.10')
  })

  it('shows total endpoint count text', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('endpoints')
  })

  it('header checkbox triggers toggleAll via DOM change', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const checkbox = wrapper.find('input[type="checkbox"]')
    await checkbox.trigger('change')
    expect((wrapper.vm as any).selected.size).toBe(3)
  })

  it('row checkbox triggers toggleSelect via DOM change', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const checkboxes = wrapper.findAll('input[type="checkbox"]')
    // second checkbox is the first row checkbox
    await checkboxes[1].trigger('change')
    expect((wrapper.vm as any).selected.has('ep-001')).toBe(true)
  })

  it('Isolate button triggers performAction via DOM click', async () => {
    const { xdrEndpointsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.toggleSelect('ep-001')
    await wrapper.vm.$nextTick()
    const isolateBtn = wrapper.findAll('button').find(b => b.text().includes('Isolate'))
    await isolateBtn!.trigger('click')
    await flushPromises()
    expect(xdrEndpointsApi.isolate).toHaveBeenCalledWith('ep-001')
  })

  it('Unisolate button triggers performAction via DOM click', async () => {
    const { xdrEndpointsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.toggleSelect('ep-002')
    await wrapper.vm.$nextTick()
    const unisolateBtn = wrapper.findAll('button').find(b => b.text().includes('Unisolate'))
    await unisolateBtn!.trigger('click')
    await flushPromises()
    expect(xdrEndpointsApi.unisolate).toHaveBeenCalledWith('ep-002')
  })
})
