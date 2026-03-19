import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/sentinel', () => ({
  sentinelIncidentApi: {
    list: vi.fn(),
  },
}))

vi.mock('vue-chartjs', () => ({
  Doughnut: { template: '<div />', props: ['data', 'options'] },
  Bar: { template: '<div />', props: ['data', 'options'] },
}))

vi.mock('chart.js', () => ({
  Chart: { register: vi.fn() },
  ArcElement: {}, Tooltip: {}, Legend: {}, BarElement: {}, CategoryScale: {}, LinearScale: {},
}))

vi.mock('../../../utils/formatters', () => ({
  relativeTime: vi.fn((v) => v ?? ''),
  formatEpoch: vi.fn((v) => `${v}`),
}))

import { sentinelIncidentApi } from '@/api/sentinel'
import SentinelDashboardView from '@/views/sentinel/SentinelDashboardView.vue'

const mockIncidents = [
  {
    name: 'inc-001',
    properties: {
      title: 'High Severity Alert',
      status: 'New',
      severity: 'High',
      providerName: 'Microsoft',
      createdTimeUtc: '2026-01-01T00:00:00Z',
      additionalData: { alertsCount: 3, alertProductNames: ['Defender', 'Sentinel'] },
    },
  },
  {
    name: 'inc-002',
    properties: {
      title: 'Medium Active Incident',
      status: 'Active',
      severity: 'Medium',
      providerName: 'Azure',
      createdTimeUtc: '2026-01-02T00:00:00Z',
      additionalData: { alertsCount: 1, alertProductNames: ['Defender'] },
    },
  },
  {
    name: 'inc-003',
    properties: {
      title: 'Low Closed Incident',
      status: 'Closed',
      severity: 'Low',
      providerName: 'Azure',
      createdTimeUtc: '2026-01-03T00:00:00Z',
      additionalData: { alertsCount: 2, alertProductNames: ['Sentinel'] },
    },
  },
  {
    name: 'inc-004',
    properties: {
      title: 'Informational Incident',
      status: 'New',
      severity: 'Informational',
      providerName: 'Microsoft',
      createdTimeUtc: '2026-01-04T00:00:00Z',
      additionalData: { alertsCount: 0, alertProductNames: [] },
    },
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/sentinel/incidents', component: { template: '<div />' } },
    { path: '/sentinel/incidents/:id', component: { template: '<div />' } },
  ],
})

const globalOpts = {
  plugins: [router],
  stubs: { LoadingSkeleton: true, RouterLink: true },
}

describe('SentinelDashboardView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(sentinelIncidentApi.list).mockResolvedValue({ value: mockIncidents } as any)
  })

  it('renders the page header', () => {
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    expect(wrapper.text()).toContain('Microsoft Sentinel Dashboard')
  })

  it('shows all four summary card labels', async () => {
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('Open Incidents')
    expect(wrapper.text()).toContain('Active Incidents')
    expect(wrapper.text()).toContain('Closed Incidents')
    expect(wrapper.text()).toContain('Total Alerts')
  })

  it('calls sentinelIncidentApi.list on mount', async () => {
    mount(SentinelDashboardView, { global: globalOpts })
    await flushPromises()
    expect(sentinelIncidentApi.list).toHaveBeenCalledTimes(1)
  })

  it('fetchAll sets loading to false after success', async () => {
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('fetchAll populates incidents', async () => {
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).incidents).toHaveLength(4)
  })

  it('fetchAll sets error message on failure', async () => {
    vi.mocked(sentinelIncidentApi.list).mockRejectedValue(new Error('Network error'))
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('Network error')
  })

  it('fetchAll sets generic error when non-Error thrown', async () => {
    vi.mocked(sentinelIncidentApi.list).mockRejectedValue('something')
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('Failed to fetch data')
  })

  it('fetchAll handles null value in response', async () => {
    vi.mocked(sentinelIncidentApi.list).mockResolvedValue({ value: null } as any)
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).incidents).toEqual([])
  })

  it('openCount computed returns count of New incidents', async () => {
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).openCount).toBe(2)
  })

  it('activeCount computed returns count of Active incidents', async () => {
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).activeCount).toBe(1)
  })

  it('closedCount computed returns count of Closed incidents', async () => {
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).closedCount).toBe(1)
  })

  it('totalAlerts computed sums alertsCount across all incidents', async () => {
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).totalAlerts).toBe(6)
  })

  it('severityBadgeClass returns correct class for high', async () => {
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('high')).toBe('bg-red-500/15 text-red-400')
    expect((wrapper.vm as any).severityBadgeClass('High')).toBe('bg-red-500/15 text-red-400')
  })

  it('severityBadgeClass returns correct class for medium', async () => {
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('medium')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('severityBadgeClass returns correct class for low', async () => {
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('low')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('severityBadgeClass returns correct class for informational', async () => {
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('informational')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('severityBadgeClass returns default class for unknown severity', async () => {
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('unknown')).toBe('bg-gray-500/15 text-gray-400')
    expect((wrapper.vm as any).severityBadgeClass('')).toBe('bg-gray-500/15 text-gray-400')
    expect((wrapper.vm as any).severityBadgeClass(null as any)).toBe('bg-gray-500/15 text-gray-400')
  })

  it('severityChartData computed groups incidents by severity', async () => {
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    await flushPromises()
    const data = (wrapper.vm as any).severityChartData
    expect(data.labels).toContain('High')
    expect(data.labels).toContain('Medium')
    expect(data.labels).toContain('Low')
    expect(data.labels).toContain('Informational')
    expect(data.datasets[0].data).toHaveLength(data.labels.length)
  })

  it('severityChartData excludes zero-count severities', async () => {
    vi.mocked(sentinelIncidentApi.list).mockResolvedValue({
      value: [
        { name: 'inc-x', properties: { title: 'X', status: 'New', severity: 'High', providerName: 'P', createdTimeUtc: '', additionalData: { alertsCount: 0, alertProductNames: [] } } },
      ],
    } as any)
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    await flushPromises()
    const data = (wrapper.vm as any).severityChartData
    expect(data.labels).toEqual(['High'])
    expect(data.labels).not.toContain('Medium')
  })

  it('severityChartData assigns correct colors', async () => {
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    await flushPromises()
    const data = (wrapper.vm as any).severityChartData
    const highIdx = data.labels.indexOf('High')
    expect(data.datasets[0].backgroundColor[highIdx]).toBe('#EF4444')
    const medIdx = data.labels.indexOf('Medium')
    expect(data.datasets[0].backgroundColor[medIdx]).toBe('#F97316')
    const lowIdx = data.labels.indexOf('Low')
    expect(data.datasets[0].backgroundColor[lowIdx]).toBe('#EAB308')
    const infoIdx = data.labels.indexOf('Informational')
    expect(data.datasets[0].backgroundColor[infoIdx]).toBe('#3B82F6')
  })

  it('alertsByProductChartData groups incidents by product name', async () => {
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    await flushPromises()
    const data = (wrapper.vm as any).alertsByProductChartData
    // Defender appears in 2 incidents, Sentinel in 2
    expect(data.labels).toContain('Defender')
    expect(data.labels).toContain('Sentinel')
    const defIdx = data.labels.indexOf('Defender')
    expect(data.datasets[0].data[defIdx]).toBe(2)
  })

  it('alertsByProductChartData returns empty labels when no incidents', async () => {
    vi.mocked(sentinelIncidentApi.list).mockResolvedValue({ value: [] } as any)
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    await flushPromises()
    const data = (wrapper.vm as any).alertsByProductChartData
    expect(data.labels).toEqual([])
  })

  it('fetchAll can be called again via refresh button', async () => {
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    await flushPromises()
    const refreshBtn = wrapper.find('button')
    await refreshBtn.trigger('click')
    await flushPromises()
    expect(sentinelIncidentApi.list).toHaveBeenCalledTimes(2)
  })

  it('shows error banner when error is set', async () => {
    vi.mocked(sentinelIncidentApi.list).mockRejectedValue(new Error('API down'))
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('API down')
  })

  it('summaryCards computed returns four cards with correct values', async () => {
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    await flushPromises()
    const cards = (wrapper.vm as any).summaryCards
    expect(cards).toHaveLength(4)
    expect(cards[0].label).toBe('Open Incidents')
    expect(cards[0].value).toBe(2)
    expect(cards[1].label).toBe('Active Incidents')
    expect(cards[1].value).toBe(1)
    expect(cards[2].label).toBe('Closed Incidents')
    expect(cards[2].value).toBe(1)
    expect(cards[3].label).toBe('Total Alerts')
    expect(cards[3].value).toBe(6)
  })

  it('totalAlerts defaults missing alertsCount to 0', async () => {
    vi.mocked(sentinelIncidentApi.list).mockResolvedValue({
      value: [
        { name: 'inc-no-alerts', properties: { title: 'X', status: 'New', severity: 'Low', providerName: 'P', createdTimeUtc: '', additionalData: {} } },
      ],
    } as any)
    const wrapper = mount(SentinelDashboardView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).totalAlerts).toBe(0)
  })
})
