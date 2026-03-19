import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/splunk', () => ({
  splunkNotableApi: {
    list: vi.fn(),
    update: vi.fn(),
  },
}))

import { splunkNotableApi } from '@/api/splunk'
import SplunkNotablesView from '@/views/splunk/SplunkNotablesView.vue'

const makeNotable = (overrides: Record<string, any> = {}) => ({
  event_id: 'notable-default',
  rule_name: 'Default Rule',
  severity: 'medium',
  urgency: 'medium',
  status: '1',
  status_label: 'New',
  owner: 'unassigned',
  dest: 'HOST-001',
  time: '1700000000',
  _time: '1700000000',
  description: 'Default description',
  drilldown_search: 'search index=main',
  rule_title: 'Default',
  security_domain: 'endpoint',
  src: '',
  user: 'admin',
  ...overrides,
})

const mockNotables = [
  makeNotable({ event_id: 'n-001', rule_name: 'Brute Force Detected', severity: 'critical', status: '1', dest: 'SERVER-A' }),
  makeNotable({ event_id: 'n-002', rule_name: 'Lateral Movement', severity: 'high', status: '2', dest: 'WKSTN-B' }),
  makeNotable({ event_id: 'n-003', rule_name: 'Phishing Email', severity: 'medium', status: '3', dest: 'MAIL-C' }),
  makeNotable({ event_id: 'n-004', rule_name: 'Data Exfiltration', severity: 'low', status: '4', dest: 'LAPTOP-D' }),
  makeNotable({ event_id: 'n-005', rule_name: 'Config Change', severity: 'medium', status: '5', dest: 'DC-E' }),
]

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/splunk/notables/:id', component: { template: '<div />' } },
  ],
})

const globalOpts = {
  plugins: [router],
  stubs: { LoadingSkeleton: true, RouterLink: true },
}

describe('SplunkNotablesView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(splunkNotableApi.list).mockResolvedValue(mockNotables as any)
    vi.mocked(splunkNotableApi.update).mockResolvedValue(undefined as any)
  })

  it('renders the page header', () => {
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    expect(wrapper.text()).toContain('Notable Events')
  })

  it('calls splunkNotableApi.list on mount', async () => {
    mount(SplunkNotablesView, { global: globalOpts })
    await flushPromises()
    expect(splunkNotableApi.list).toHaveBeenCalledTimes(1)
  })

  it('fetchNotables populates notables ref', async () => {
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).notables).toHaveLength(5)
  })

  it('fetchNotables sets loading false after success', async () => {
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('fetchNotables sets error on API failure', async () => {
    vi.mocked(splunkNotableApi.list).mockRejectedValue(new Error('API error'))
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('API error')
  })

  it('fetchNotables sets generic error for non-Error throws', async () => {
    vi.mocked(splunkNotableApi.list).mockRejectedValue('bad')
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('Failed to fetch notables')
  })

  it('fetchNotables sets loading false even after error', async () => {
    vi.mocked(splunkNotableApi.list).mockRejectedValue(new Error('fail'))
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('fetchNotables can be called via refresh button', async () => {
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    await flushPromises()
    const btn = wrapper.find('button')
    await btn.trigger('click')
    await flushPromises()
    expect(splunkNotableApi.list).toHaveBeenCalledTimes(2)
  })

  it('severityBadgeClass returns correct class for critical', () => {
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('critical')).toBe('bg-red-500/15 text-red-400')
    expect((wrapper.vm as any).severityBadgeClass('Critical')).toBe('bg-red-500/15 text-red-400')
  })

  it('severityBadgeClass returns correct class for high', () => {
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('high')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('severityBadgeClass returns correct class for medium', () => {
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('medium')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('severityBadgeClass returns correct class for low', () => {
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('low')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('severityBadgeClass returns default class for unknown', () => {
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('informational')).toBe('bg-gray-500/15 text-gray-400')
    expect((wrapper.vm as any).severityBadgeClass('')).toBe('bg-gray-500/15 text-gray-400')
    expect((wrapper.vm as any).severityBadgeClass(null as any)).toBe('bg-gray-500/15 text-gray-400')
  })

  it('statusLabel returns correct label for known statuses', () => {
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    expect((wrapper.vm as any).statusLabel('1')).toBe('New')
    expect((wrapper.vm as any).statusLabel('2')).toBe('In Progress')
    expect((wrapper.vm as any).statusLabel('3')).toBe('Pending')
    expect((wrapper.vm as any).statusLabel('4')).toBe('Resolved')
    expect((wrapper.vm as any).statusLabel('5')).toBe('Closed')
  })

  it('statusLabel returns raw value for unknown status', () => {
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    expect((wrapper.vm as any).statusLabel('99')).toBe('99')
    expect((wrapper.vm as any).statusLabel('')).toBe('')
  })

  it('formatTime returns empty string for falsy input', () => {
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    expect((wrapper.vm as any).formatTime('')).toBe('')
    expect((wrapper.vm as any).formatTime(null as any)).toBe('')
    expect((wrapper.vm as any).formatTime(undefined as any)).toBe('')
  })

  it('formatTime converts epoch string to locale string', () => {
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    const ts = '1700000000'
    const result = (wrapper.vm as any).formatTime(ts)
    expect(result).toBeTruthy()
    expect(typeof result).toBe('string')
    // Should be a formatted date string
    expect(result).not.toBe(ts)
  })

  it('filtered computed returns all notables when no filter set', async () => {
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).filtered).toHaveLength(5)
  })

  it('filtered computed filters by statusFilter', async () => {
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).statusFilter = '1'
    await wrapper.vm.$nextTick()
    const filtered = (wrapper.vm as any).filtered
    expect(filtered).toHaveLength(1)
    expect(filtered[0].event_id).toBe('n-001')
  })

  it('filtered computed filters by severityFilter', async () => {
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).severityFilter = 'medium'
    await wrapper.vm.$nextTick()
    const filtered = (wrapper.vm as any).filtered
    expect(filtered).toHaveLength(2)
    expect(filtered.every((n: any) => n.severity === 'medium')).toBe(true)
  })

  it('filtered computed applies both status and severity filters', async () => {
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).statusFilter = '2'
    ;(wrapper.vm as any).severityFilter = 'high'
    await wrapper.vm.$nextTick()
    const filtered = (wrapper.vm as any).filtered
    expect(filtered).toHaveLength(1)
    expect(filtered[0].event_id).toBe('n-002')
  })

  it('filtered returns empty when filters match nothing', async () => {
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).statusFilter = '5'
    ;(wrapper.vm as any).severityFilter = 'critical'
    await wrapper.vm.$nextTick()
    expect((wrapper.vm as any).filtered).toHaveLength(0)
  })

  it('updateStatus calls splunkNotableApi.update and refetches', async () => {
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    await flushPromises()
    await (wrapper.vm as any).updateStatus('n-001', '2')
    await flushPromises()
    expect(splunkNotableApi.update).toHaveBeenCalledWith('n-001', { status: '2' })
    expect(splunkNotableApi.list).toHaveBeenCalledTimes(2)
  })

  it('updateStatus sets error on API failure', async () => {
    vi.mocked(splunkNotableApi.update).mockRejectedValue(new Error('Update failed'))
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    await flushPromises()
    await (wrapper.vm as any).updateStatus('n-001', '2')
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('Update failed')
  })

  it('updateStatus sets generic error for non-Error throws', async () => {
    vi.mocked(splunkNotableApi.update).mockRejectedValue('nope')
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    await flushPromises()
    await (wrapper.vm as any).updateStatus('n-001', '3')
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('Failed to update notable status')
  })

  it('shows no-match message when filtered is empty', async () => {
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).statusFilter = '5'
    ;(wrapper.vm as any).severityFilter = 'critical'
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('No notable events match the current filters')
  })

  it('shows error banner when error is set', async () => {
    vi.mocked(splunkNotableApi.list).mockRejectedValue(new Error('DB error'))
    const wrapper = mount(SplunkNotablesView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('DB error')
  })
})
