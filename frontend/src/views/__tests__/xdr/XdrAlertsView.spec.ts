import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

const mockAlertsList = vi.hoisted(() => vi.fn())

vi.mock('../../../api/cortex', () => ({
  xdrAlertsApi: { list: mockAlertsList },
}))

vi.mock('../../../utils/formatters', () => ({
  formatEpoch: vi.fn((v) => `${v}`),
  relativeTime: vi.fn((v) => v ?? ''),
}))

import XdrAlertsView from '@/views/xdr/XdrAlertsView.vue'
import { xdrAlertsApi } from '@/api/cortex'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/xdr/alerts/:id', component: { template: '<div />' } },
  ],
})

const stubs = { LoadingSkeleton: true, EmptyState: true }

const FAKE_ALERTS = [
  { alert_id: 'a-1', name: 'Malware Detected', severity: 'high', source: 'XDR Analytics', status: 'active', detection_timestamp: 1700000000000, host_name: 'WKSTN-001', description: 'Malware found', category: 'Malware', action: 'DETECTED', local_ip: '10.0.0.1' },
  { alert_id: 'a-2', name: 'Suspicious Script', severity: 'medium', source: 'Cortex XSIAM', status: 'active', detection_timestamp: 1700000001000, host_name: 'WKSTN-002', description: 'Script execution', category: 'Exploit', action: 'BLOCKED', local_ip: '10.0.0.2' },
  { alert_id: 'a-3', name: 'Critical Threat', severity: 'critical', source: 'XDR Analytics', status: 'resolved', detection_timestamp: 1700000002000, host_name: 'SERVER-001', description: 'Critical', category: 'Ransomware', action: 'DETECTED', local_ip: '10.0.0.3' },
]

describe('XdrAlertsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockAlertsList.mockResolvedValue({ reply: { alerts: FAKE_ALERTS, total_count: 3, result_count: 3 } })
  })

  it('renders the page header', () => {
    const wrapper = mount(XdrAlertsView, { global: { plugins: [router], stubs } })
    expect(wrapper.text()).toContain('Alerts')
  })

  it('calls xdrAlertsApi.list on mount', async () => {
    mount(XdrAlertsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(xdrAlertsApi.list).toHaveBeenCalled()
  })

  it('renders alert name after loading', async () => {
    const wrapper = mount(XdrAlertsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('Malware Detected')
  })

  it('renders host name', async () => {
    const wrapper = mount(XdrAlertsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('WKSTN-001')
  })

  it('sets loading to false after fetch', async () => {
    const wrapper = mount(XdrAlertsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('populates alerts array from API', async () => {
    const wrapper = mount(XdrAlertsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).alerts).toHaveLength(3)
  })

  it('severityBadgeClass returns red for critical', () => {
    const wrapper = mount(XdrAlertsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).severityBadgeClass('critical')).toBe('bg-red-500/15 text-red-400')
  })

  it('severityBadgeClass returns orange for high', () => {
    const wrapper = mount(XdrAlertsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).severityBadgeClass('high')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('severityBadgeClass returns yellow for medium', () => {
    const wrapper = mount(XdrAlertsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).severityBadgeClass('medium')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('severityBadgeClass returns blue for low', () => {
    const wrapper = mount(XdrAlertsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).severityBadgeClass('low')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('severityBadgeClass returns gray for unknown severity', () => {
    const wrapper = mount(XdrAlertsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).severityBadgeClass('unknown')).toBe('bg-gray-500/15 text-gray-400')
  })

  it('filteredAlerts returns all alerts when no filters set', async () => {
    const wrapper = mount(XdrAlertsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).filteredAlerts).toHaveLength(3)
  })

  it('filteredAlerts filters by severity', async () => {
    const wrapper = mount(XdrAlertsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    ;(wrapper.vm as any).filterSeverity = 'high'
    expect((wrapper.vm as any).filteredAlerts).toHaveLength(1)
    expect((wrapper.vm as any).filteredAlerts[0].alert_id).toBe('a-1')
  })

  it('filteredAlerts filters by source', async () => {
    const wrapper = mount(XdrAlertsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    ;(wrapper.vm as any).filterSource = 'XDR Analytics'
    expect((wrapper.vm as any).filteredAlerts).toHaveLength(2)
  })

  it('filteredAlerts applies both severity and source filters', async () => {
    const wrapper = mount(XdrAlertsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    ;(wrapper.vm as any).filterSeverity = 'high'
    ;(wrapper.vm as any).filterSource = 'XDR Analytics'
    expect((wrapper.vm as any).filteredAlerts).toHaveLength(1)
  })

  it('uniqueSources returns sorted unique sources', async () => {
    const wrapper = mount(XdrAlertsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const sources = (wrapper.vm as any).uniqueSources
    expect(sources).toContain('XDR Analytics')
    expect(sources).toContain('Cortex XSIAM')
    // Check for uniqueness: XDR Analytics appears twice in alerts but once in uniqueSources
    expect(sources.filter((s: string) => s === 'XDR Analytics')).toHaveLength(1)
  })

  it('totalCount is set from API total_count', async () => {
    const wrapper = mount(XdrAlertsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).totalCount).toBe(3)
  })

  it('fetchAlerts uses alerts.length as fallback when total_count absent', async () => {
    mockAlertsList.mockResolvedValueOnce({ reply: { alerts: FAKE_ALERTS } })
    const wrapper = mount(XdrAlertsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).totalCount).toBe(3)
  })
})
