import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/elastic', () => ({
  esEndpointsApi: {
    list: vi.fn().mockResolvedValue({
      data: [
        {
          agent_id: 'ep-1',
          hostname: 'WKSTN-001',
          os: 'Windows 10.0',
          agent_status: 'online',
          isolation_status: 'normal',
          agent_version: '8.10.0',
          last_checkin: '2025-01-01T00:00:00Z',
          policy_name: 'Default Policy',
          ip_address: '10.0.0.1',
        },
        {
          agent_id: 'ep-2',
          hostname: 'WKSTN-002',
          os: 'macOS 13.0',
          agent_status: 'offline',
          isolation_status: 'isolated',
          agent_version: '8.10.0',
          last_checkin: '2025-01-02T00:00:00Z',
          policy_name: 'Custom Policy',
          ip_address: '10.0.0.2',
        },
      ],
      total: 2,
    }),
    isolate: vi.fn().mockResolvedValue({}),
    unisolate: vi.fn().mockResolvedValue({}),
  },
}))

import EsEndpointsView from '@/views/elastic/EsEndpointsView.vue'
import { esEndpointsApi } from '@/api/elastic'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/elastic/endpoints', component: { template: '<div />' } },
  ],
})

const STUBS = {
  LoadingSkeleton: true,
  EmptyState: true,
  RouterLink: { template: '<a><slot /></a>' },
  Teleport: true,
}

describe('EsEndpointsView', () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    await router.push('/')
    await router.isReady()
  })

  it('renders the page header with Endpoints title', async () => {
    const wrapper = mount(EsEndpointsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Endpoints')
  })

  it('calls esEndpointsApi.list on mount', async () => {
    mount(EsEndpointsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(esEndpointsApi.list).toHaveBeenCalledWith({ page: 1, per_page: 25 })
  })

  it('displays loaded endpoint hostnames after mount', async () => {
    const wrapper = mount(EsEndpointsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('WKSTN-001')
    expect(wrapper.text()).toContain('WKSTN-002')
  })

  it('displays total endpoint count', async () => {
    const wrapper = mount(EsEndpointsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('2')
  })

  // statusBadgeClass — all branches
  it('statusBadgeClass returns green for online', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('online')).toBe('bg-green-500/15 text-green-400')
  })

  it('statusBadgeClass returns gray for offline', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('offline')).toBe('bg-gray-500/15 text-gray-400')
  })

  it('statusBadgeClass returns yellow for enrolling', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('enrolling')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('statusBadgeClass returns orange for unenrolling', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('unenrolling')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('statusBadgeClass returns gray for unknown status', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('unknown')).toBe('bg-gray-500/15 text-gray-400')
  })

  // isolationBadgeClass — all branches
  it('isolationBadgeClass returns red for isolated', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).isolationBadgeClass('isolated')).toBe('bg-red-500/15 text-red-400')
  })

  it('isolationBadgeClass returns green for normal', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).isolationBadgeClass('normal')).toBe('bg-green-500/15 text-green-400')
  })

  it('isolationBadgeClass returns gray for unknown isolation status', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).isolationBadgeClass('pending')).toBe('bg-gray-500/15 text-gray-400')
  })

  // fetchEndpoints — explicit call with page parameter
  it('fetchEndpoints can be called with a page argument', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esEndpointsApi.list).mockClear()
    await (wrapper.vm as any).fetchEndpoints(2)
    await flushPromises()
    expect(esEndpointsApi.list).toHaveBeenCalledWith({ page: 2, per_page: 25 })
  })

  it('fetchEndpoints sets loading to false after success', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    await (wrapper.vm as any).fetchEndpoints()
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('fetchEndpoints sets loading to false on error', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esEndpointsApi.list).mockRejectedValueOnce(new Error('API error'))
    try { await (wrapper.vm as any).fetchEndpoints() } catch { /* expected */ }
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  // toggleAll — select all
  it('toggleAll selects all endpoints when none are selected', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    expect(vm.selected.size).toBe(0)
    vm.toggleAll()
    expect(vm.selected.has('ep-1')).toBe(true)
    expect(vm.selected.has('ep-2')).toBe(true)
  })

  // toggleAll — deselect all when allSelected
  it('toggleAll deselects all endpoints when all are selected', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    // First call: select all
    vm.toggleAll()
    expect(vm.allSelected).toBe(true)
    // Second call: deselect all
    vm.toggleAll()
    expect(vm.selected.size).toBe(0)
  })

  // toggleSelect — add to selection
  it('toggleSelect adds an endpoint to selection', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.toggleSelect('ep-1')
    expect(vm.selected.has('ep-1')).toBe(true)
  })

  // toggleSelect — remove from selection
  it('toggleSelect removes an endpoint from selection when already selected', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.toggleSelect('ep-1')
    expect(vm.selected.has('ep-1')).toBe(true)
    vm.toggleSelect('ep-1')
    expect(vm.selected.has('ep-1')).toBe(false)
  })

  // allSelected computed
  it('allSelected is false when no endpoints are selected', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).allSelected).toBe(false)
  })

  it('allSelected is true when all endpoints are selected', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.toggleAll()
    expect(vm.allSelected).toBe(true)
  })

  it('allSelected is false when only some endpoints are selected', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.toggleSelect('ep-1')
    expect(vm.allSelected).toBe(false)
  })

  // hasPrev / hasNext computed
  it('hasPrev is false on page 1', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).hasPrev).toBe(false)
  })

  it('hasPrev is true on page 2', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    await (wrapper.vm as any).fetchEndpoints(2)
    await flushPromises()
    expect((wrapper.vm as any).hasPrev).toBe(true)
  })

  it('hasNext is false when total fits on one page', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).hasNext).toBe(false)
  })

  it('hasNext is true when total exceeds per-page limit', async () => {
    vi.mocked(esEndpointsApi.list).mockResolvedValueOnce({
      page: 1, per_page: 25,
      data: [{ agent_id: 'ep-1', hostname: 'WKSTN-001', os: 'Windows', agent_status: 'online', isolation_status: 'normal', agent_version: '8.10.0', policy_name: 'Default', ip_address: '10.0.0.1', last_checkin: '2025-01-01T00:00:00Z' }],
      total: 100,
    })
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).hasNext).toBe(true)
  })

  // performAction — empty guard
  it('performAction does nothing when no endpoints are selected', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esEndpointsApi.isolate).mockClear()
    await (wrapper.vm as any).performAction('isolate')
    await flushPromises()
    expect(esEndpointsApi.isolate).not.toHaveBeenCalled()
  })

  // performAction — isolate
  it('performAction isolate calls esEndpointsApi.isolate with selected ids', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.toggleSelect('ep-1')
    vm.toggleSelect('ep-2')
    await vm.performAction('isolate')
    await flushPromises()
    expect(esEndpointsApi.isolate).toHaveBeenCalledWith(
      expect.arrayContaining(['ep-1', 'ep-2']),
      'Isolated from UI',
    )
  })

  // performAction — unisolate
  it('performAction unisolate calls esEndpointsApi.unisolate with selected ids', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.toggleSelect('ep-1')
    await vm.performAction('unisolate')
    await flushPromises()
    expect(esEndpointsApi.unisolate).toHaveBeenCalledWith(['ep-1'], 'Released from UI')
  })

  it('performAction clears selection after completing', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.toggleSelect('ep-1')
    await vm.performAction('isolate')
    await flushPromises()
    expect(vm.selected.size).toBe(0)
  })

  it('performAction refreshes endpoints after action', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.toggleSelect('ep-1')
    vi.mocked(esEndpointsApi.list).mockClear()
    await vm.performAction('isolate')
    await flushPromises()
    expect(esEndpointsApi.list).toHaveBeenCalled()
  })

  it('performAction sets loading to false on error', async () => {
    vi.mocked(esEndpointsApi.isolate).mockRejectedValueOnce(new Error('isolate failed'))
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.toggleSelect('ep-1')
    try { await vm.performAction('isolate') } catch { /* expected */ }
    await flushPromises()
    expect(vm.loading).toBe(false)
  })

  it('shows empty state when no endpoints are returned', async () => {
    vi.mocked(esEndpointsApi.list).mockResolvedValueOnce({ page: 1, per_page: 25, data: [], total: 0 })
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.html()).toContain('empty-state-stub')
  })

  it('Refresh button triggers fetchEndpoints via DOM click', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esEndpointsApi.list).mockClear()
    const refreshBtn = wrapper.findAll('button').find(b => b.text().includes('Refresh'))
    await refreshBtn!.trigger('click')
    await flushPromises()
    expect(esEndpointsApi.list).toHaveBeenCalled()
  })

  it('header checkbox triggers toggleAll via DOM change', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const headerCheckbox = wrapper.find('input[type="checkbox"]')
    await headerCheckbox.trigger('change')
    expect((wrapper.vm as any).selected.size).toBeGreaterThan(0)
  })

  it('row checkbox triggers toggleSelect via DOM change', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const checkboxes = wrapper.findAll('input[type="checkbox"]')
    if (checkboxes.length > 1) {
      await checkboxes[1].trigger('change')
      expect((wrapper.vm as any).selected.size).toBe(1)
    }
  })

  it('Isolate button triggers performAction via DOM click', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.toggleSelect('ep-1')
    await wrapper.vm.$nextTick()
    vi.mocked(esEndpointsApi.isolate).mockClear()
    const isolateBtn = wrapper.findAll('button').find(b => b.text().includes('Isolate'))
    await isolateBtn!.trigger('click')
    await flushPromises()
    expect(esEndpointsApi.isolate).toHaveBeenCalled()
  })

  it('Release button triggers performAction unisolate via DOM click', async () => {
    const wrapper = mount(EsEndpointsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.toggleSelect('ep-1')
    await wrapper.vm.$nextTick()
    vi.mocked(esEndpointsApi.unisolate).mockClear()
    const releaseBtn = wrapper.findAll('button').find(b => b.text().includes('Release'))
    await releaseBtn!.trigger('click')
    await flushPromises()
    expect(esEndpointsApi.unisolate).toHaveBeenCalled()
  })
})
