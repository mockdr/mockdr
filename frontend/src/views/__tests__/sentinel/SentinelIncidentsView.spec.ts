import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/sentinel', () => ({
  sentinelIncidentApi: {
    list: vi.fn(),
  },
}))

vi.mock('../../../utils/formatters', () => ({
  relativeTime: vi.fn((v) => v ?? ''),
  formatEpoch: vi.fn((v) => `${v}`),
}))

import { sentinelIncidentApi } from '@/api/sentinel'
import SentinelIncidentsView from '@/views/sentinel/SentinelIncidentsView.vue'

const mockIncidents = [
  {
    name: 'inc-001',
    properties: {
      title: 'SQL Injection Attempt',
      status: 'New',
      severity: 'High',
      providerName: 'Microsoft',
      createdTimeUtc: '2026-01-01T00:00:00Z',
      additionalData: { alertsCount: 5 },
      owner: { assignedTo: 'alice@contoso.com' },
    },
  },
  {
    name: 'inc-002',
    properties: {
      title: 'Brute Force Attack',
      status: 'Active',
      severity: 'Medium',
      providerName: 'Azure',
      createdTimeUtc: '2026-01-02T00:00:00Z',
      additionalData: { alertsCount: 2 },
      owner: { assignedTo: 'bob@contoso.com' },
    },
  },
  {
    name: 'inc-003',
    properties: {
      title: 'Phishing Email',
      status: 'Closed',
      severity: 'Low',
      providerName: 'Defender',
      createdTimeUtc: '2026-01-03T00:00:00Z',
      additionalData: { alertsCount: 1 },
      owner: null,
    },
  },
  {
    name: 'inc-004',
    properties: {
      title: 'Informational Event',
      status: 'New',
      severity: 'Informational',
      providerName: 'Sentinel',
      createdTimeUtc: '2026-01-04T00:00:00Z',
      additionalData: { alertsCount: 0 },
      owner: { assignedTo: '' },
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
  stubs: { LoadingSkeleton: true, EmptyState: true, RouterLink: true },
}

describe('SentinelIncidentsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(sentinelIncidentApi.list).mockResolvedValue({ value: mockIncidents } as any)
  })

  it('renders the page header', () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    expect(wrapper.text()).toContain('Incidents')
  })

  it('calls sentinelIncidentApi.list on mount', async () => {
    mount(SentinelIncidentsView, { global: globalOpts })
    await flushPromises()
    expect(sentinelIncidentApi.list).toHaveBeenCalledTimes(1)
  })

  it('fetchIncidents populates incidents ref', async () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).incidents).toHaveLength(4)
  })

  it('fetchIncidents sets loading false after success', async () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('fetchIncidents handles null value in response', async () => {
    vi.mocked(sentinelIncidentApi.list).mockResolvedValue({ value: null } as any)
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).incidents).toEqual([])
  })

  it('fetchIncidents can be manually called again via refresh button', async () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    await flushPromises()
    const btn = wrapper.find('button')
    await btn.trigger('click')
    await flushPromises()
    expect(sentinelIncidentApi.list).toHaveBeenCalledTimes(2)
  })

  it('severityBadgeClass returns correct class for high', () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('high')).toBe('bg-red-500/15 text-red-400')
    expect((wrapper.vm as any).severityBadgeClass('High')).toBe('bg-red-500/15 text-red-400')
  })

  it('severityBadgeClass returns correct class for medium', () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('medium')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('severityBadgeClass returns correct class for low', () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('low')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('severityBadgeClass returns correct class for informational', () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('informational')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('severityBadgeClass returns default class for unknown', () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('unknown')).toBe('bg-gray-500/15 text-gray-400')
    expect((wrapper.vm as any).severityBadgeClass('')).toBe('bg-gray-500/15 text-gray-400')
    expect((wrapper.vm as any).severityBadgeClass(null as any)).toBe('bg-gray-500/15 text-gray-400')
  })

  it('statusBadgeClass returns correct class for new', () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    expect((wrapper.vm as any).statusBadgeClass('new')).toBe('bg-blue-500/15 text-blue-400')
    expect((wrapper.vm as any).statusBadgeClass('New')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('statusBadgeClass returns correct class for active', () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    expect((wrapper.vm as any).statusBadgeClass('active')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('statusBadgeClass returns correct class for closed', () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    expect((wrapper.vm as any).statusBadgeClass('closed')).toBe('bg-green-500/15 text-green-400')
  })

  it('statusBadgeClass returns default class for unknown', () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    expect((wrapper.vm as any).statusBadgeClass('other')).toBe('bg-gray-500/15 text-gray-400')
    expect((wrapper.vm as any).statusBadgeClass(null as any)).toBe('bg-gray-500/15 text-gray-400')
  })

  it('filteredIncidents returns all incidents when no filter set', async () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).filteredIncidents).toHaveLength(4)
  })

  it('filteredIncidents filters by status New', async () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).filterStatus = 'New'
    await wrapper.vm.$nextTick()
    const filtered = (wrapper.vm as any).filteredIncidents
    expect(filtered).toHaveLength(2)
    expect(filtered.every((i: any) => i.properties.status === 'New')).toBe(true)
  })

  it('filteredIncidents filters by status Active', async () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).filterStatus = 'Active'
    await wrapper.vm.$nextTick()
    const filtered = (wrapper.vm as any).filteredIncidents
    expect(filtered).toHaveLength(1)
    expect(filtered[0].properties.status).toBe('Active')
  })

  it('filteredIncidents filters by status Closed', async () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).filterStatus = 'Closed'
    await wrapper.vm.$nextTick()
    expect((wrapper.vm as any).filteredIncidents).toHaveLength(1)
  })

  it('filteredIncidents filters by severity High', async () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).filterSeverity = 'High'
    await wrapper.vm.$nextTick()
    const filtered = (wrapper.vm as any).filteredIncidents
    expect(filtered).toHaveLength(1)
    expect(filtered[0].properties.severity).toBe('High')
  })

  it('filteredIncidents filters by severity Informational', async () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).filterSeverity = 'Informational'
    await wrapper.vm.$nextTick()
    expect((wrapper.vm as any).filteredIncidents).toHaveLength(1)
  })

  it('filteredIncidents applies both status and severity filters together', async () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).filterStatus = 'New'
    ;(wrapper.vm as any).filterSeverity = 'Informational'
    await wrapper.vm.$nextTick()
    const filtered = (wrapper.vm as any).filteredIncidents
    expect(filtered).toHaveLength(1)
    expect(filtered[0].name).toBe('inc-004')
  })

  it('filteredIncidents returns empty when filters match nothing', async () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).filterStatus = 'Closed'
    ;(wrapper.vm as any).filterSeverity = 'High'
    await wrapper.vm.$nextTick()
    expect((wrapper.vm as any).filteredIncidents).toHaveLength(0)
  })

  it('shows count text with filtered and total incidents', async () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('4 of 4 incidents')
  })

  it('shows filtered count when status filter is applied', async () => {
    const wrapper = mount(SentinelIncidentsView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).filterStatus = 'Active'
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('1 of 4 incidents')
  })
})
