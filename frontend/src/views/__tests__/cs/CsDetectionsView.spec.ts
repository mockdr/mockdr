import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

const mockQueryIds = vi.hoisted(() => vi.fn())

const mockGetEntities = vi.hoisted(() => vi.fn())

vi.mock('../../../api/crowdstrike', () => ({
  ensureCsAuth: vi.fn().mockResolvedValue(undefined),
  csDetectionsApi: {
    queryIds: mockQueryIds,
    getEntities: mockGetEntities,
    update: vi.fn().mockResolvedValue({ resources: [], errors: [] }),
  },
}))

vi.mock('../../../utils/formatters', () => ({
  relativeTime: vi.fn((v: string) => v ?? ''),
}))

import CsDetectionsView from '@/views/cs/CsDetectionsView.vue'
import { ensureCsAuth, csDetectionsApi } from '@/api/crowdstrike'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/crowdstrike/detections/:id', component: { template: '<div />' } },
  ],
})

const stubs = { LoadingSkeleton: true, EmptyState: true }

describe('CsDetectionsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQueryIds.mockResolvedValue({
      resources: ['det-id-1'],
      meta: { pagination: { total: 1 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    mockGetEntities.mockResolvedValue({
      resources: [
        {
          composite_id: 'det-id-1',
          status: 'new',
          max_severity: 85,
          max_severity_displayname: 'Critical',
          behaviors: [{ scenario: 'malware-execution', tactic: 'Execution', technique: 'T1059' }],
          device: { device_id: 'dev-1', hostname: 'WKSTN-001', platform_name: 'Windows', external_ip: '1.2.3.4' },
          created_timestamp: '2025-01-01T00:00:00Z',
        },
      ],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
  })

  it('renders the page header', () => {
    const wrapper = mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    expect(wrapper.text()).toContain('Detections')
  })

  it('calls ensureCsAuth and queryIds on mount', async () => {
    mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(ensureCsAuth).toHaveBeenCalled()
    expect(csDetectionsApi.queryIds).toHaveBeenCalledWith(expect.objectContaining({ offset: 0, limit: 25 }))
  })

  it('calls getEntities with IDs returned from queryIds', async () => {
    mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(csDetectionsApi.getEntities).toHaveBeenCalledWith(['det-id-1'])
  })

  it('renders hostname from detection device', async () => {
    const wrapper = mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('WKSTN-001')
  })

  it('renders severity displayname', async () => {
    const wrapper = mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('Critical')
  })

  it('renders detection status', async () => {
    const wrapper = mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('new')
  })

  it('renders scenario from behaviors array', async () => {
    const wrapper = mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('malware-execution')
  })

  it('sets loading to false after fetch', async () => {
    const wrapper = mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('severityBadgeClass returns red for severity >= 80', () => {
    const wrapper = mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).severityBadgeClass(80)).toBe('bg-red-500/15 text-red-400')
    expect((wrapper.vm as any).severityBadgeClass(100)).toBe('bg-red-500/15 text-red-400')
  })

  it('severityBadgeClass returns orange for severity 60-79', () => {
    const wrapper = mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).severityBadgeClass(60)).toBe('bg-orange-500/15 text-orange-400')
    expect((wrapper.vm as any).severityBadgeClass(79)).toBe('bg-orange-500/15 text-orange-400')
  })

  it('severityBadgeClass returns yellow for severity 40-59', () => {
    const wrapper = mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).severityBadgeClass(40)).toBe('bg-yellow-500/15 text-yellow-400')
    expect((wrapper.vm as any).severityBadgeClass(59)).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('severityBadgeClass returns blue for severity 20-39', () => {
    const wrapper = mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).severityBadgeClass(20)).toBe('bg-blue-500/15 text-blue-400')
    expect((wrapper.vm as any).severityBadgeClass(39)).toBe('bg-blue-500/15 text-blue-400')
  })

  it('severityBadgeClass returns gray for severity < 20', () => {
    const wrapper = mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).severityBadgeClass(0)).toBe('bg-gray-500/15 text-gray-400')
    expect((wrapper.vm as any).severityBadgeClass(19)).toBe('bg-gray-500/15 text-gray-400')
  })

  it('statusBadgeClass returns correct class for each known status', () => {
    const wrapper = mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    const vm = wrapper.vm as any
    expect(vm.statusBadgeClass('new')).toBe('bg-blue-500/15 text-blue-400')
    expect(vm.statusBadgeClass('in_progress')).toBe('bg-yellow-500/15 text-yellow-400')
    expect(vm.statusBadgeClass('true_positive')).toBe('bg-red-500/15 text-red-400')
    expect(vm.statusBadgeClass('false_positive')).toBe('bg-green-500/15 text-green-400')
    expect(vm.statusBadgeClass('closed')).toBe('bg-gray-500/15 text-gray-400')
  })

  it('statusBadgeClass returns default gray for unknown status', () => {
    const wrapper = mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusBadgeClass('unknown_status')).toBe('bg-gray-500/15 text-gray-400')
  })

  it('fetchDetections with append=false resets detections when IDs are empty', async () => {
    const wrapper = mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    expect(vm.detections.length).toBe(1)
    mockQueryIds.mockResolvedValueOnce({
      resources: [],
      meta: { pagination: { total: 0 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    await vm.fetchDetections()
    await flushPromises()
    expect(vm.detections.length).toBe(0)
  })

  it('fetchDetections(true) appends detections to existing list', async () => {
    const wrapper = mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    const initialCount = vm.detections.length
    mockQueryIds.mockResolvedValueOnce({
      resources: ['det-id-2'],
      meta: { pagination: { total: 5 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    mockGetEntities.mockResolvedValueOnce({
      resources: [
        { composite_id: 'det-id-2', status: 'closed', max_severity: 20, max_severity_displayname: 'Low', behaviors: [], device: null, created_timestamp: '2025-02-01T00:00:00Z' },
      ],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    await vm.fetchDetections(true)
    await flushPromises()
    expect(vm.detections.length).toBe(initialCount + 1)
  })

  it('hasMore is true when offset < total', async () => {
    mockQueryIds.mockResolvedValue({
      resources: ['det-id-1'],
      meta: { pagination: { total: 100 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    const wrapper = mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).hasMore).toBe(true)
  })

  it('hasMore is false when offset equals total', async () => {
    mockQueryIds.mockResolvedValue({
      resources: ['det-id-1'],
      meta: { pagination: { total: 1 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    const wrapper = mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).hasMore).toBe(false)
  })

  it('fetchDetections builds filter when filterSeverity is set', async () => {
    const wrapper = mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.filterSeverity = 'High'
    vi.clearAllMocks()
    await vm.fetchDetections()
    await flushPromises()
    expect(csDetectionsApi.queryIds).toHaveBeenCalledWith(
      expect.objectContaining({ filter: "max_severity_displayname:'High'" }),
    )
  })

  it('fetchDetections builds filter when filterStatus is set', async () => {
    const wrapper = mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.filterStatus = 'in_progress'
    vi.clearAllMocks()
    await vm.fetchDetections()
    await flushPromises()
    expect(csDetectionsApi.queryIds).toHaveBeenCalledWith(
      expect.objectContaining({ filter: "status:'in_progress'" }),
    )
  })

  it('fetchDetections builds combined filter when both severity and status are set', async () => {
    const wrapper = mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.filterSeverity = 'Critical'
    vm.filterStatus = 'new'
    vi.clearAllMocks()
    await vm.fetchDetections()
    await flushPromises()
    expect(csDetectionsApi.queryIds).toHaveBeenCalledWith(
      expect.objectContaining({ filter: "max_severity_displayname:'Critical'+status:'new'" }),
    )
  })

  it('uses resources.length as total fallback when pagination is absent', async () => {
    mockQueryIds.mockResolvedValueOnce({
      resources: ['d1', 'd2'],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    } as any)
    mockGetEntities.mockResolvedValueOnce({
      resources: [
        { composite_id: 'd1', status: 'new', max_severity: 50, max_severity_displayname: 'Medium', behaviors: [], device: null, created_timestamp: '' },
        { composite_id: 'd2', status: 'new', max_severity: 50, max_severity_displayname: 'Medium', behaviors: [], device: null, created_timestamp: '' },
      ],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    } as any)
    const wrapper = mount(CsDetectionsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).total).toBe(2)
  })
})
