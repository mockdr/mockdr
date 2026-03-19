import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/crowdstrike', () => ({
  ensureCsAuth: vi.fn().mockResolvedValue(undefined),
  csHostsApi: {
    queryIds: vi.fn().mockResolvedValue({
      resources: ['host-1', 'host-2'],
      meta: { pagination: { total: 2, offset: 0, limit: 100 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    }),
    getEntities: vi.fn().mockResolvedValue({
      resources: [
        { device_id: 'host-1', hostname: 'WKSTN-001', platform_name: 'Windows', status: 'normal' },
        { device_id: 'host-2', hostname: 'MAC-001', platform_name: 'Mac', status: 'normal' },
      ],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    }),
  },
  csDetectionsApi: {
    queryIds: vi.fn().mockResolvedValue({
      resources: ['det-1'],
      meta: { pagination: { total: 1, offset: 0, limit: 100 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    }),
    getEntities: vi.fn().mockResolvedValue({
      resources: [
        {
          composite_id: 'det-1',
          status: 'new',
          max_severity: 85,
          max_severity_displayname: 'Critical',
          device: { hostname: 'WKSTN-001' },
          behaviors: [{ scenario: 'test-scenario' }],
        },
      ],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    }),
  },
  csIncidentsApi: {
    queryIds: vi.fn().mockResolvedValue({
      resources: ['inc-1'],
      meta: { pagination: { total: 1, offset: 0, limit: 100 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    }),
    getEntities: vi.fn().mockResolvedValue({
      resources: [
        {
          incident_id: 'inc-1',
          name: 'Test Incident',
          status: 20,
          fine_score: 75,
          hosts: [{ hostname: 'WKSTN-001' }],
        },
      ],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    }),
  },
}))

vi.mock('vue-chartjs', () => ({
  Doughnut: { template: '<div class="mock-doughnut" />', props: ['data', 'options'] },
}))

vi.mock('chart.js', () => ({
  Chart: { register: vi.fn() },
  ArcElement: {},
  Tooltip: {},
  Legend: {},
}))

import CsDashboardView from '@/views/cs/CsDashboardView.vue'
import { ensureCsAuth, csHostsApi, csDetectionsApi, csIncidentsApi } from '@/api/crowdstrike'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/crowdstrike/detections', component: { template: '<div />' } },
    { path: '/crowdstrike/detections/:id', component: { template: '<div />' } },
    { path: '/crowdstrike/incidents', component: { template: '<div />' } },
  ],
})

const stubs = { LoadingSkeleton: true }

describe('CsDashboardView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the page header', () => {
    const wrapper = mount(CsDashboardView, { global: { plugins: [router], stubs } })
    expect(wrapper.text()).toContain('CrowdStrike Dashboard')
  })

  it('shows all summary card labels', () => {
    const wrapper = mount(CsDashboardView, { global: { plugins: [router], stubs } })
    expect(wrapper.text()).toContain('Total Hosts')
    expect(wrapper.text()).toContain('Detections')
    expect(wrapper.text()).toContain('Incidents')
  })

  it('calls ensureCsAuth and all three queryIds APIs on mount', async () => {
    mount(CsDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(ensureCsAuth).toHaveBeenCalled()
    expect(csHostsApi.queryIds).toHaveBeenCalledWith({ limit: 100 })
    expect(csDetectionsApi.queryIds).toHaveBeenCalledWith({ limit: 100 })
    expect(csIncidentsApi.queryIds).toHaveBeenCalledWith({ limit: 100 })
  })

  it('calls getEntities for all three APIs after IDs are resolved', async () => {
    mount(CsDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(csHostsApi.getEntities).toHaveBeenCalledWith(['host-1', 'host-2'])
    expect(csDetectionsApi.getEntities).toHaveBeenCalledWith(['det-1'])
    expect(csIncidentsApi.getEntities).toHaveBeenCalledWith(['inc-1'])
  })

  it('populates hostCount, detectionCount, incidentCount from pagination total', async () => {
    const wrapper = mount(CsDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    expect(vm.hostCount).toBe(2)
    expect(vm.detectionCount).toBe(1)
    expect(vm.incidentCount).toBe(1)
  })

  it('displays loaded counts in the DOM', async () => {
    const wrapper = mount(CsDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('2')
    expect(wrapper.text()).toContain('1')
  })

  it('sets loading to false after successful fetchAll', async () => {
    const wrapper = mount(CsDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('calls fetchAll again when Refresh button is clicked', async () => {
    const wrapper = mount(CsDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    vi.clearAllMocks()
    await wrapper.find('button').trigger('click')
    await flushPromises()
    expect(ensureCsAuth).toHaveBeenCalled()
  })

  it('sets error message when API throws', async () => {
    vi.mocked(csHostsApi.queryIds).mockRejectedValueOnce(new Error('Network failure'))
    const wrapper = mount(CsDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('Network failure')
  })

  it('shows error banner when error is set', async () => {
    vi.mocked(csHostsApi.queryIds).mockRejectedValueOnce(new Error('API error'))
    const wrapper = mount(CsDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('API error')
  })

  it('sets error to generic message when non-Error is thrown', async () => {
    vi.mocked(csHostsApi.queryIds).mockRejectedValueOnce('bad string error')
    const wrapper = mount(CsDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('Failed to fetch data')
  })

  it('computes platformChartData correctly from host entities', async () => {
    const wrapper = mount(CsDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    const data = vm.platformChartData
    expect(data.labels).toContain('Windows')
    expect(data.labels).toContain('Mac')
    expect(data.datasets[0].data).toBeDefined()
  })

  it('computes severityChartData correctly from detection entities', async () => {
    const wrapper = mount(CsDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    const data = vm.severityChartData
    expect(data.labels).toContain('Critical')
    expect(data.datasets[0].data[0]).toBe(1)
  })

  it('computes incidentStatusChartData correctly from incident entities', async () => {
    const wrapper = mount(CsDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    const data = vm.incidentStatusChartData
    expect(data.labels).toContain('New')
    expect(data.datasets[0].data[0]).toBe(1)
  })

  it('computes incidentStatusChartData with unknown status fallback', async () => {
    vi.mocked(csIncidentsApi.getEntities).mockResolvedValueOnce({
      resources: [
        { incident_id: 'inc-x', name: 'X', status: 99, fine_score: 10, hosts: [] },
      ],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    } as any)
    const wrapper = mount(CsDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const data = (wrapper.vm as any).incidentStatusChartData
    expect(data.labels).toContain('Status 99')
  })

  it('computes summaryCards array with correct labels and icons', async () => {
    const wrapper = mount(CsDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    const cards = vm.summaryCards
    expect(cards).toHaveLength(3)
    expect(cards[0].label).toBe('Total Hosts')
    expect(cards[1].label).toBe('Detections')
    expect(cards[2].label).toBe('Incidents')
  })

  it('skips getEntities calls when queryIds returns empty resources', async () => {
    vi.mocked(csHostsApi.queryIds).mockResolvedValueOnce({
      resources: [],
      meta: { pagination: { total: 0, offset: 0, limit: 100 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    vi.mocked(csDetectionsApi.queryIds).mockResolvedValueOnce({
      resources: [],
      meta: { pagination: { total: 0, offset: 0, limit: 100 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    vi.mocked(csIncidentsApi.queryIds).mockResolvedValueOnce({
      resources: [],
      meta: { pagination: { total: 0, offset: 0, limit: 100 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    mount(CsDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    // getEntities should NOT be called when no IDs returned
    expect(csHostsApi.getEntities).not.toHaveBeenCalled()
  })

  it('uses resources.length as fallback when pagination total is absent', async () => {
    vi.mocked(csHostsApi.queryIds).mockResolvedValueOnce({
      resources: ['h1', 'h2', 'h3'],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    } as any)
    vi.mocked(csDetectionsApi.queryIds).mockResolvedValueOnce({
      resources: [],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    } as any)
    vi.mocked(csIncidentsApi.queryIds).mockResolvedValueOnce({
      resources: [],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    } as any)
    vi.mocked(csHostsApi.getEntities).mockResolvedValueOnce({
      resources: [
        { device_id: 'h1', hostname: 'H1', platform_name: 'Linux', status: 'normal' },
        { device_id: 'h2', hostname: 'H2', platform_name: 'Linux', status: 'normal' },
        { device_id: 'h3', hostname: 'H3', platform_name: 'Linux', status: 'normal' },
      ],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    } as any)
    const wrapper = mount(CsDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).hostCount).toBe(3)
  })

  it('clears error on subsequent successful fetchAll', async () => {
    vi.mocked(csHostsApi.queryIds).mockRejectedValueOnce(new Error('Temporary error'))
    const wrapper = mount(CsDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('Temporary error')
    // Reset to success
    vi.mocked(csHostsApi.queryIds).mockResolvedValue({
      resources: [],
      meta: { pagination: { total: 0, offset: 0, limit: 100 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    await (wrapper.vm as any).fetchAll()
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('')
  })

  it('shows "No data" placeholder when no detections loaded', async () => {
    vi.mocked(csDetectionsApi.queryIds).mockResolvedValueOnce({
      resources: [],
      meta: { pagination: { total: 0, offset: 0, limit: 100 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    vi.mocked(csIncidentsApi.queryIds).mockResolvedValueOnce({
      resources: [],
      meta: { pagination: { total: 0, offset: 0, limit: 100 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    const wrapper = mount(CsDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('No data')
  })

  it('shows "No recent detections" when detections array is empty', async () => {
    vi.mocked(csDetectionsApi.queryIds).mockResolvedValueOnce({
      resources: [],
      meta: { pagination: { total: 0, offset: 0, limit: 100 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    vi.mocked(csIncidentsApi.queryIds).mockResolvedValueOnce({
      resources: [],
      meta: { pagination: { total: 0, offset: 0, limit: 100 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    const wrapper = mount(CsDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('No recent detections')
  })

  it('severityChartData only includes labels with count > 0', async () => {
    const wrapper = mount(CsDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const data = (wrapper.vm as any).severityChartData
    // Only 'Critical' has count > 0
    expect(data.labels).toContain('Critical')
    expect(data.labels).not.toContain('High')
    expect(data.labels).not.toContain('Medium')
  })

  it('platformChartData always returns all three platform labels', async () => {
    const wrapper = mount(CsDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const data = (wrapper.vm as any).platformChartData
    // The component initialises counts with Windows/Mac/Linux so all three labels are always present
    expect(data.labels).toContain('Windows')
    expect(data.labels).toContain('Mac')
    expect(data.labels).toContain('Linux')
    expect(data.datasets[0].data).toHaveLength(3)
  })
})
