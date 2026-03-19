import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/splunk', () => ({
  splunkNotableApi: {
    list: vi.fn(),
  },
  splunkIndexApi: {
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

import { splunkNotableApi, splunkIndexApi } from '@/api/splunk'
import SplunkDashboardView from '@/views/splunk/SplunkDashboardView.vue'

const mockNotables = [
  { event_id: 'n-001', rule_name: 'Threat A', severity: 'critical', status: '1', owner: 'alice', dest: 'HOST-A', time: '1700000000', _time: '1700000000', description: '', drilldown_search: '', rule_title: '', security_domain: 'endpoint', src: '', urgency: 'critical', user: 'admin', status_label: 'New' },
  { event_id: 'n-002', rule_name: 'Threat B', severity: 'high', status: '2', owner: 'bob', dest: 'HOST-B', time: '1700000001', _time: '1700000001', description: '', drilldown_search: '', rule_title: '', security_domain: 'endpoint', src: '', urgency: 'high', user: 'bob', status_label: 'In Progress' },
  { event_id: 'n-003', rule_name: 'Threat C', severity: 'medium', status: '3', owner: 'carol', dest: 'HOST-C', time: '1700000002', _time: '1700000002', description: '', drilldown_search: '', rule_title: '', security_domain: 'endpoint', src: '', urgency: 'medium', user: 'carol', status_label: 'Pending' },
  { event_id: 'n-004', rule_name: 'Threat D', severity: 'low', status: '4', owner: 'dave', dest: 'HOST-D', time: '1700000003', _time: '1700000003', description: '', drilldown_search: '', rule_title: '', security_domain: 'endpoint', src: '', urgency: 'low', user: 'dave', status_label: 'Resolved' },
]

const mockIndexes = [
  { name: 'sentinelone', content: { totalEventCount: '1000', currentDBSizeMB: '100', datatype: 'event', disabled: false } },
  { name: 'crowdstrike', content: { totalEventCount: '800', currentDBSizeMB: '80', datatype: 'event', disabled: false } },
  { name: 'msdefender', content: { totalEventCount: '600', currentDBSizeMB: '60', datatype: 'event', disabled: false } },
  { name: 'custom_index', content: { totalEventCount: '200', currentDBSizeMB: '20', datatype: 'event', disabled: false } },
]

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/splunk/notables', component: { template: '<div />' } },
    { path: '/splunk/notables/:id', component: { template: '<div />' } },
  ],
})

const globalOpts = {
  plugins: [router],
  stubs: { LoadingSkeleton: true, RouterLink: true },
}

describe('SplunkDashboardView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(splunkNotableApi.list).mockResolvedValue(mockNotables as any)
    vi.mocked(splunkIndexApi.list).mockResolvedValue({ entry: mockIndexes } as any)
  })

  it('renders the dashboard header', () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    expect(wrapper.text()).toContain('Splunk SIEM Dashboard')
  })

  it('calls splunkNotableApi.list and splunkIndexApi.list on mount', async () => {
    mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    expect(splunkNotableApi.list).toHaveBeenCalledTimes(1)
    expect(splunkIndexApi.list).toHaveBeenCalledTimes(1)
  })

  it('fetchAll populates notables ref', async () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).notables).toHaveLength(4)
  })

  it('fetchAll populates indexes ref', async () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).indexes).toHaveLength(4)
  })

  it('fetchAll sets loading false after success', async () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('fetchAll calculates openNotables (status 1 or 2)', async () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    // n-001 (status 1) and n-002 (status 2) are open
    expect((wrapper.vm as any).openNotables).toBe(2)
  })

  it('fetchAll calculates totalEvents from all index event counts', async () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    // 1000 + 800 + 600 + 200 = 2600
    expect((wrapper.vm as any).totalEvents).toBe(2600)
  })

  it('fetchAll handles null entry in index response', async () => {
    vi.mocked(splunkIndexApi.list).mockResolvedValue({ entry: null } as any)
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).indexes).toEqual([])
    expect((wrapper.vm as any).totalEvents).toBe(0)
  })

  it('fetchAll sets error on API failure', async () => {
    vi.mocked(splunkNotableApi.list).mockRejectedValue(new Error('Network error'))
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('Network error')
  })

  it('fetchAll sets generic error for non-Error throws', async () => {
    vi.mocked(splunkNotableApi.list).mockRejectedValue('bad')
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('Failed to fetch data')
  })

  it('fetchAll sets loading false even after error', async () => {
    vi.mocked(splunkNotableApi.list).mockRejectedValue(new Error('fail'))
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('fetchAll can be called via refresh button', async () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    const btn = wrapper.find('button')
    await btn.trigger('click')
    await flushPromises()
    expect(splunkNotableApi.list).toHaveBeenCalledTimes(2)
    expect(splunkIndexApi.list).toHaveBeenCalledTimes(2)
  })

  it('summaryCards computed returns four cards', async () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    const cards = (wrapper.vm as any).summaryCards
    expect(cards).toHaveLength(4)
  })

  it('summaryCards has correct labels', async () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    const cards = (wrapper.vm as any).summaryCards
    expect(cards[0].label).toBe('Total Events')
    expect(cards[1].label).toBe('Notable Events (Open)')
    expect(cards[2].label).toBe('Indexes')
    expect(cards[3].label).toBe('HEC Status')
  })

  it('summaryCards has correct values', async () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    const cards = (wrapper.vm as any).summaryCards
    expect(cards[0].value).toBe(2600)
    expect(cards[1].value).toBe(2)
    expect(cards[2].value).toBe(4)
    expect(cards[3].value).toBe('Active')
  })

  it('severityBadgeClass returns correct class for critical', () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('critical')).toBe('bg-red-500/15 text-red-400')
  })

  it('severityBadgeClass returns correct class for high', () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('high')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('severityBadgeClass returns correct class for medium', () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('medium')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('severityBadgeClass returns correct class for low', () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('low')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('severityBadgeClass returns default class for unknown', () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('unknown')).toBe('bg-gray-500/15 text-gray-400')
    expect((wrapper.vm as any).severityBadgeClass('')).toBe('bg-gray-500/15 text-gray-400')
    expect((wrapper.vm as any).severityBadgeClass(null as any)).toBe('bg-gray-500/15 text-gray-400')
  })

  it('statusLabel returns correct labels for known statuses', () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    expect((wrapper.vm as any).statusLabel('1')).toBe('New')
    expect((wrapper.vm as any).statusLabel('2')).toBe('In Progress')
    expect((wrapper.vm as any).statusLabel('3')).toBe('Pending')
    expect((wrapper.vm as any).statusLabel('4')).toBe('Resolved')
    expect((wrapper.vm as any).statusLabel('5')).toBe('Closed')
  })

  it('statusLabel returns raw value for unknown status', () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    expect((wrapper.vm as any).statusLabel('99')).toBe('99')
    expect((wrapper.vm as any).statusLabel('')).toBe('')
  })

  it('formatTime returns empty string for falsy input', () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    expect((wrapper.vm as any).formatTime('')).toBe('')
    expect((wrapper.vm as any).formatTime(null as any)).toBe('')
  })

  it('formatTime converts epoch string to locale date string', () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    const result = (wrapper.vm as any).formatTime('1700000000')
    expect(result).toBeTruthy()
    expect(typeof result).toBe('string')
    expect(result).not.toBe('1700000000')
  })

  it('eventsByIndexChartData only includes known EDR indexes', async () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    const data = (wrapper.vm as any).eventsByIndexChartData
    // custom_index is not in the EDR list, should be excluded
    expect(data.labels).toContain('sentinelone')
    expect(data.labels).toContain('crowdstrike')
    expect(data.labels).toContain('msdefender')
    expect(data.labels).not.toContain('custom_index')
  })

  it('eventsByIndexChartData maps event counts correctly', async () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    const data = (wrapper.vm as any).eventsByIndexChartData
    const s1Idx = data.labels.indexOf('sentinelone')
    expect(data.datasets[0].data[s1Idx]).toBe(1000)
  })

  it('notableSeverityChartData groups notables by severity', async () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    const data = (wrapper.vm as any).notableSeverityChartData
    expect(data.labels).toContain('critical')
    expect(data.labels).toContain('high')
    expect(data.labels).toContain('medium')
    expect(data.labels).toContain('low')
  })

  it('notableSeverityChartData only includes severities with count > 0', async () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    const data = (wrapper.vm as any).notableSeverityChartData
    // informational has 0 count
    expect(data.labels).not.toContain('informational')
  })

  it('notableSeverityChartData defaults unknown severity to medium', async () => {
    vi.mocked(splunkNotableApi.list).mockResolvedValue([
      { ...mockNotables[0], severity: undefined },
    ] as any)
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    const data = (wrapper.vm as any).notableSeverityChartData
    expect(data.labels).toContain('medium')
  })

  it('shows error banner when error is set', async () => {
    vi.mocked(splunkNotableApi.list).mockRejectedValue(new Error('Service unavailable'))
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('Service unavailable')
  })

  it('shows summary card labels in template', async () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('Total Events')
    expect(wrapper.text()).toContain('Notable Events (Open)')
    expect(wrapper.text()).toContain('Indexes')
  })

  it('renders "Recent Notable Events" section heading', async () => {
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('Recent Notable Events')
  })

  it('shows "No notable events" when notables list is empty', async () => {
    vi.mocked(splunkNotableApi.list).mockResolvedValue([] as any)
    const wrapper = mount(SplunkDashboardView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('No notable events')
  })
})
