import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

const mockIncidentsList = vi.hoisted(() => vi.fn())
const mockAlertsList = vi.hoisted(() => vi.fn())
const mockEndpointsList = vi.hoisted(() => vi.fn())

vi.mock('../../../api/cortex', () => ({
  xdrIncidentsApi: { list: mockIncidentsList },
  xdrAlertsApi: { list: mockAlertsList },
  xdrEndpointsApi: { list: mockEndpointsList },
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

vi.mock('../../../utils/formatters', () => ({
  formatEpoch: vi.fn((v) => `${v}`),
}))

import XdrDashboardView from '@/views/xdr/XdrDashboardView.vue'
import { xdrIncidentsApi, xdrAlertsApi, xdrEndpointsApi } from '@/api/cortex'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/xdr/incidents', component: { template: '<div />' } },
    { path: '/xdr/alerts', component: { template: '<div />' } },
    { path: '/xdr/endpoints', component: { template: '<div />' } },
  ],
})

const stubs = { LoadingSkeleton: true }

const FAKE_INCIDENTS = [
  { incident_id: 'inc-1', description: 'Incident 1', severity: 'critical', status: 'new', creation_time: 1700000000000 },
  { incident_id: 'inc-2', description: 'Incident 2', severity: 'high', status: 'active', creation_time: 1700000001000 },
]

const FAKE_ALERTS = [
  { alert_id: 'a-1', name: 'Alert 1', severity: 'high', source: 'XDR Analytics', status: 'active', detection_timestamp: 1700000000000, host_name: 'WKSTN-001' },
  { alert_id: 'a-2', name: 'Alert 2', severity: 'medium', source: 'Cortex XSIAM', status: 'active', detection_timestamp: 1700000001000, host_name: 'WKSTN-002' },
]

const FAKE_ENDPOINTS = [
  { endpoint_id: 'ep-1', endpoint_name: 'WKSTN-001', os_type: 'AGENT_OS_WINDOWS', endpoint_status: 'CONNECTED' },
  { endpoint_id: 'ep-2', endpoint_name: 'WKSTN-002', os_type: 'AGENT_OS_LINUX', endpoint_status: 'CONNECTED' },
]

describe('XdrDashboardView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockIncidentsList.mockResolvedValue({ reply: { incidents: FAKE_INCIDENTS, total_count: 2 } })
    mockAlertsList.mockResolvedValue({ reply: { alerts: FAKE_ALERTS, total_count: 2 } })
    mockEndpointsList.mockResolvedValue({ reply: { endpoints: FAKE_ENDPOINTS, total_count: 2 } })
  })

  it('renders the page header', () => {
    const wrapper = mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    expect(wrapper.text()).toContain('Cortex XDR Dashboard')
  })

  it('shows summary card labels', () => {
    const wrapper = mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    expect(wrapper.text()).toContain('Incidents')
    expect(wrapper.text()).toContain('Alerts')
    expect(wrapper.text()).toContain('Endpoints')
  })

  it('calls all three APIs on mount', async () => {
    mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(xdrIncidentsApi.list).toHaveBeenCalled()
    expect(xdrAlertsApi.list).toHaveBeenCalled()
    expect(xdrEndpointsApi.list).toHaveBeenCalled()
  })

  it('sets incidentCount, alertCount, endpointCount from total_count', async () => {
    const wrapper = mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    expect(vm.incidentCount).toBe(2)
    expect(vm.alertCount).toBe(2)
    expect(vm.endpointCount).toBe(2)
  })

  it('sets loading to false after fetchAll', async () => {
    const wrapper = mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('sets error message when API throws', async () => {
    mockIncidentsList.mockRejectedValueOnce(new Error('Network failure'))
    const wrapper = mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('Network failure')
  })

  it('sets generic error when non-Error is thrown', async () => {
    mockIncidentsList.mockRejectedValueOnce('bad string')
    const wrapper = mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('Failed to fetch data')
  })

  it('clears error on successful subsequent fetchAll', async () => {
    mockIncidentsList.mockRejectedValueOnce(new Error('Temp error'))
    const wrapper = mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('Temp error')
    mockIncidentsList.mockResolvedValue({ reply: { incidents: [], total_count: 0 } })
    await (wrapper.vm as any).fetchAll()
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('')
  })

  it('summaryCards computed returns 3 cards with correct labels', async () => {
    const wrapper = mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const cards = (wrapper.vm as any).summaryCards
    expect(cards).toHaveLength(3)
    expect(cards[0].label).toBe('Incidents')
    expect(cards[1].label).toBe('Alerts')
    expect(cards[2].label).toBe('Endpoints')
  })

  it('summaryCards values reflect loaded counts', async () => {
    const wrapper = mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const cards = (wrapper.vm as any).summaryCards
    expect(cards[0].value).toBe(2)
    expect(cards[1].value).toBe(2)
    expect(cards[2].value).toBe(2)
  })

  it('severityChartData includes critical and high labels', async () => {
    const wrapper = mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const data = (wrapper.vm as any).severityChartData
    expect(data.labels).toContain('critical')
    expect(data.labels).toContain('high')
  })

  it('severityChartData excludes labels with zero count', async () => {
    const wrapper = mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const data = (wrapper.vm as any).severityChartData
    expect(data.labels).not.toContain('low')
    expect(data.labels).not.toContain('medium')
  })

  it('alertSourceChartData groups by source', async () => {
    const wrapper = mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const data = (wrapper.vm as any).alertSourceChartData
    expect(data.labels).toContain('XDR Analytics')
    expect(data.labels).toContain('Cortex XSIAM')
  })

  it('endpointOsChartData groups by os_type', async () => {
    const wrapper = mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const data = (wrapper.vm as any).endpointOsChartData
    expect(data.labels).toContain('AGENT_OS_WINDOWS')
    expect(data.labels).toContain('AGENT_OS_LINUX')
  })

  it('severityBadgeClass returns red for critical', () => {
    const wrapper = mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).severityBadgeClass('critical')).toBe('bg-red-500/15 text-red-400')
  })

  it('severityBadgeClass returns orange for high', () => {
    const wrapper = mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).severityBadgeClass('high')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('severityBadgeClass returns yellow for medium', () => {
    const wrapper = mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).severityBadgeClass('medium')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('severityBadgeClass returns blue for low', () => {
    const wrapper = mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).severityBadgeClass('low')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('severityBadgeClass returns gray for unknown severity', () => {
    const wrapper = mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).severityBadgeClass('unknown')).toBe('bg-gray-500/15 text-gray-400')
  })

  it('fetchAll uses resources.length as fallback when total_count absent', async () => {
    mockIncidentsList.mockResolvedValueOnce({ reply: { incidents: FAKE_INCIDENTS } })
    mockAlertsList.mockResolvedValueOnce({ reply: { alerts: FAKE_ALERTS } })
    mockEndpointsList.mockResolvedValueOnce({ reply: { endpoints: FAKE_ENDPOINTS } })
    const wrapper = mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).incidentCount).toBe(2)
    expect((wrapper.vm as any).alertCount).toBe(2)
    expect((wrapper.vm as any).endpointCount).toBe(2)
  })

  it('fetchAll handles empty reply gracefully', async () => {
    mockIncidentsList.mockResolvedValueOnce({ reply: { incidents: [], total_count: 0 } })
    mockAlertsList.mockResolvedValueOnce({ reply: { alerts: [], total_count: 0 } })
    mockEndpointsList.mockResolvedValueOnce({ reply: { endpoints: [], total_count: 0 } })
    const wrapper = mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).incidentCount).toBe(0)
  })

  it('displays loaded incident count in the DOM', async () => {
    const wrapper = mount(XdrDashboardView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('2')
  })
})
