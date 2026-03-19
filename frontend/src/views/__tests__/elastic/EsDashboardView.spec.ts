import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

const FULL_ES_ENDPOINT_FIELDS = vi.hoisted(() => ({ os: 'Windows', agent_version: '8.0', policy_name: 'Default', ip_address: '10.0.0.1', last_checkin: '2025-01-01T00:00:00Z' }))
const FULL_ES_RULE_FIELDS = vi.hoisted(() => ({ rule_id: 'rule-x', description: '', type: 'query', tags: [], created_at: '2025-01-01T00:00:00Z', updated_at: '2025-01-01T00:00:00Z', created_by: 'elastic', interval: '5m' }))

vi.mock('../../../api/elastic', () => ({
  esEndpointsApi: {
    list: vi.fn().mockResolvedValue({
      page: 1,
      per_page: 50,
      total: 3,
      data: [
        { agent_id: 'ep-1', hostname: 'WKSTN-001', agent_status: 'online', isolation_status: 'normal', ...FULL_ES_ENDPOINT_FIELDS },
        { agent_id: 'ep-2', hostname: 'WKSTN-002', agent_status: 'offline', isolation_status: 'isolated', ...FULL_ES_ENDPOINT_FIELDS },
        { agent_id: 'ep-3', hostname: 'WKSTN-003', agent_status: 'online', isolation_status: 'normal', ...FULL_ES_ENDPOINT_FIELDS },
      ],
    }),
  },
  esRulesApi: {
    find: vi.fn().mockResolvedValue({
      page: 1,
      per_page: 50,
      total: 4,
      data: [
        { id: 'rule-1', name: 'Brute Force', severity: 'high', enabled: true, risk_score: 75, ...FULL_ES_RULE_FIELDS },
        { id: 'rule-2', name: 'Malware', severity: 'critical', enabled: false, risk_score: 95, ...FULL_ES_RULE_FIELDS },
        { id: 'rule-3', name: 'Recon', severity: 'medium', enabled: true, risk_score: 40, ...FULL_ES_RULE_FIELDS },
        { id: 'rule-4', name: 'Info Gather', severity: 'low', enabled: true, risk_score: 20, ...FULL_ES_RULE_FIELDS },
      ],
    }),
  },
  esAlertsApi: {
    search: vi.fn().mockResolvedValue({
      took: 5,
      hits: {
        hits: [
          {
            _id: 'alert-1',
            _index: '.alerts-security',
            _source: { id: 'alert-1', rule_name: 'Brute Force', severity: 'high', risk_score: 75, status: 'open', host_name: 'WKSTN-001', timestamp: '2025-01-01T00:00:00Z', rule_id: 'rule-1' },
          },
          {
            _id: 'alert-2',
            _index: '.alerts-security',
            _source: { id: 'alert-2', rule_name: 'Malware Exec', severity: 'critical', risk_score: 95, status: 'closed', host_name: 'SERVER-001', timestamp: '2025-01-02T00:00:00Z', rule_id: 'rule-2' },
          },
        ],
        total: { value: 2, relation: 'eq' },
      },
    }),
  },
  esCasesApi: {
    find: vi.fn().mockResolvedValue({ page: 1, per_page: 25, total: 5, data: [] }),
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

import EsDashboardView from '@/views/elastic/EsDashboardView.vue'
import { esEndpointsApi, esRulesApi, esAlertsApi, esCasesApi } from '@/api/elastic'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/elastic/alerts', component: { template: '<div />' } },
    { path: '/elastic/rules', component: { template: '<div />' } },
    { path: '/elastic/cases', component: { template: '<div />' } },
    { path: '/elastic/endpoints', component: { template: '<div />' } },
  ],
})

const STUBS = {
  LoadingSkeleton: true,
  RouterLink: { template: '<a><slot /></a>' },
  Teleport: true,
}

describe('EsDashboardView', () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    await router.push('/')
    await router.isReady()
  })

  it('renders the Elastic Security Dashboard header', async () => {
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('Elastic Security Dashboard')
  })

  it('calls all four APIs on mount', async () => {
    mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(esEndpointsApi.list).toHaveBeenCalledWith({ per_page: 50 })
    expect(esRulesApi.find).toHaveBeenCalledWith({ per_page: 50 })
    expect(esAlertsApi.search).toHaveBeenCalledWith(
      expect.objectContaining({ query: { match_all: {} }, size: 50 })
    )
    expect(esCasesApi.find).toHaveBeenCalledWith({ per_page: 1 })
  })

  it('displays the Endpoints summary card with correct count', async () => {
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('Endpoints')
    expect(wrapper.text()).toContain('3')
  })

  it('displays the Detection Rules summary card with correct count', async () => {
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('Detection Rules')
    expect(wrapper.text()).toContain('4')
  })

  it('displays the Alerts summary card with correct count', async () => {
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('Alerts')
    expect(wrapper.text()).toContain('2')
  })

  it('displays the Cases summary card with correct count', async () => {
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('Cases')
    expect(wrapper.text()).toContain('5')
  })

  it('shows Recent Alerts section', async () => {
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('Recent Alerts')
  })

  it('shows Detection Rules section', async () => {
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('Detection Rules')
  })

  it('displays recent alert rule names in the table', async () => {
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('Brute Force')
  })

  it('displays rule names in the rules section', async () => {
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('Malware')
  })

  // fetchAll function — explicit call
  it('fetchAll can be called explicitly to refresh all data', async () => {
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esEndpointsApi.list).mockClear()
    vi.mocked(esRulesApi.find).mockClear()
    vi.mocked(esAlertsApi.search).mockClear()
    vi.mocked(esCasesApi.find).mockClear()
    await (wrapper.vm as any).fetchAll()
    await flushPromises()
    expect(esEndpointsApi.list).toHaveBeenCalled()
    expect(esRulesApi.find).toHaveBeenCalled()
    expect(esAlertsApi.search).toHaveBeenCalled()
    expect(esCasesApi.find).toHaveBeenCalled()
  })

  it('fetchAll sets loading to false after success', async () => {
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    await (wrapper.vm as any).fetchAll()
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('fetchAll sets error message on failure', async () => {
    vi.mocked(esEndpointsApi.list).mockRejectedValueOnce(new Error('Network error'))
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    // The initial mount call will have triggered the error; check it was set
    expect((wrapper.vm as any).error).toBe('Network error')
  })

  it('fetchAll clears error on subsequent success', async () => {
    vi.mocked(esEndpointsApi.list).mockRejectedValueOnce(new Error('Network error'))
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('Network error')
    // Now call fetchAll again with a working mock
    await (wrapper.vm as any).fetchAll()
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('')
  })

  it('fetchAll sets loading to false even on error', async () => {
    vi.mocked(esAlertsApi.search).mockRejectedValueOnce(new Error('alerts failed'))
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('shows error banner when error is set', async () => {
    vi.mocked(esEndpointsApi.list).mockRejectedValueOnce(new Error('Fetch failed'))
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('Fetch failed')
  })

  // summaryCards computed
  it('summaryCards computed returns four cards with correct labels', async () => {
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const cards = (wrapper.vm as any).summaryCards
    expect(cards).toHaveLength(4)
    const labels = cards.map((c: { label: string }) => c.label)
    expect(labels).toContain('Endpoints')
    expect(labels).toContain('Detection Rules')
    expect(labels).toContain('Alerts')
    expect(labels).toContain('Cases')
  })

  // statusChartData computed
  it('statusChartData computed groups endpoints by agent_status', async () => {
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const chartData = (wrapper.vm as any).statusChartData
    expect(chartData.labels).toContain('online')
    expect(chartData.labels).toContain('offline')
    const onlineIndex = chartData.labels.indexOf('online')
    expect(chartData.datasets[0].data[onlineIndex]).toBe(2)
  })

  // ruleSeverityChartData computed
  it('ruleSeverityChartData computed groups rules by severity', async () => {
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const chartData = (wrapper.vm as any).ruleSeverityChartData
    // critical, high, medium, low all have at least 1
    expect(chartData.labels.length).toBeGreaterThan(0)
    expect(chartData.datasets[0].data.length).toBeGreaterThan(0)
  })

  it('ruleSeverityChartData filters out severity counts of 0', async () => {
    vi.mocked(esRulesApi.find).mockResolvedValueOnce({
      page: 1, per_page: 50, total: 1,
      data: [
        { id: 'r1', name: 'Rule 1', severity: 'critical', enabled: true, risk_score: 95, ...FULL_ES_RULE_FIELDS },
      ],
    })
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const chartData = (wrapper.vm as any).ruleSeverityChartData
    // Only 'critical' should be in labels (high/medium/low are 0 and filtered)
    expect(chartData.labels).toEqual(['critical'])
  })

  // alertStatusChartData computed
  it('alertStatusChartData computed groups alerts by status', async () => {
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const chartData = (wrapper.vm as any).alertStatusChartData
    expect(chartData.labels).toContain('open')
    expect(chartData.labels).toContain('closed')
  })

  it('shows "No data" placeholder for endpoint chart when no endpoints loaded', async () => {
    vi.mocked(esEndpointsApi.list).mockResolvedValueOnce({ page: 1, per_page: 50, total: 0, data: [] })
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('No data')
  })

  it('shows "No recent alerts" when alerts list is empty', async () => {
    vi.mocked(esAlertsApi.search).mockResolvedValueOnce({
      took: 1,
      hits: { hits: [], total: { value: 0, relation: 'eq' } },
    })
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('No recent alerts')
  })

  it('shows "No detection rules" when rules list is empty', async () => {
    vi.mocked(esRulesApi.find).mockResolvedValueOnce({ page: 1, per_page: 50, total: 0, data: [] })
    const wrapper = mount(EsDashboardView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('No detection rules')
  })
})
