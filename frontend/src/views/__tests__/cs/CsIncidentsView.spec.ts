import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

const mockQueryIds = vi.hoisted(() => vi.fn())

const mockGetEntities = vi.hoisted(() => vi.fn())

vi.mock('../../../api/crowdstrike', () => ({
  ensureCsAuth: vi.fn().mockResolvedValue(undefined),
  csIncidentsApi: {
    queryIds: mockQueryIds,
    getEntities: mockGetEntities,
    action: vi.fn().mockResolvedValue({ resources: [], errors: [] }),
  },
}))

vi.mock('../../../utils/formatters', () => ({
  relativeTime: vi.fn((v: string) => v ?? ''),
}))

import CsIncidentsView from '@/views/cs/CsIncidentsView.vue'
import { ensureCsAuth, csIncidentsApi } from '@/api/crowdstrike'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/crowdstrike/incidents', component: { template: '<div />' } },
  ],
})

const stubs = { LoadingSkeleton: true, EmptyState: true }

describe('CsIncidentsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQueryIds.mockResolvedValue({
      resources: ['inc-id-1'],
      meta: { pagination: { total: 1 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    mockGetEntities.mockResolvedValue({
      resources: [
        {
          incident_id: 'inc-id-1',
          name: 'Test Incident Alpha',
          description: 'Suspicious lateral movement detected',
          status: 20,
          fine_score: 75,
          hosts: [{ hostname: 'WKSTN-001' }, { hostname: 'WKSTN-002' }],
          tactics: ['Lateral Movement', 'Credential Access', 'Execution', 'Discovery'],
          created: '2025-01-01T00:00:00Z',
        },
      ],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
  })

  it('renders the page header', () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    expect(wrapper.text()).toContain('Incidents')
  })

  it('calls ensureCsAuth and queryIds on mount', async () => {
    mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(ensureCsAuth).toHaveBeenCalled()
    expect(csIncidentsApi.queryIds).toHaveBeenCalledWith(expect.objectContaining({ offset: 0, limit: 25 }))
  })

  it('calls getEntities with resolved IDs', async () => {
    mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(csIncidentsApi.getEntities).toHaveBeenCalledWith(['inc-id-1'])
  })

  it('renders incident name after loading', async () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('Test Incident Alpha')
  })

  it('renders incident description', async () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('Suspicious lateral movement detected')
  })

  it('renders host names from incident', async () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('WKSTN-001')
  })

  it('renders tactic badges (max 3 shown)', async () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('Lateral Movement')
    expect(wrapper.text()).toContain('Credential Access')
    expect(wrapper.text()).toContain('Execution')
  })

  it('shows +N overflow indicator when more than 3 tactics', async () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    // 4 tactics total, only 3 shown, so +1 indicator should appear
    expect(wrapper.text()).toContain('+1')
  })

  it('sets loading to false after fetch', async () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('statusLabel returns "New" for status 20', () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusLabel(20)).toBe('New')
  })

  it('statusLabel returns "Reopened" for status 25', () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusLabel(25)).toBe('Reopened')
  })

  it('statusLabel returns "In Progress" for status 30', () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusLabel(30)).toBe('In Progress')
  })

  it('statusLabel returns "Closed" for status 40', () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusLabel(40)).toBe('Closed')
  })

  it('statusLabel returns "Status N" for unknown status codes', () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusLabel(99)).toBe('Status 99')
  })

  it('statusBadgeClass returns blue for status 20 (New)', () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusBadgeClass(20)).toBe('bg-blue-500/15 text-blue-400')
  })

  it('statusBadgeClass returns orange for status 25 (Reopened)', () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusBadgeClass(25)).toBe('bg-orange-500/15 text-orange-400')
  })

  it('statusBadgeClass returns yellow for status 30 (In Progress)', () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusBadgeClass(30)).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('statusBadgeClass returns green for status 40 (Closed)', () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusBadgeClass(40)).toBe('bg-green-500/15 text-green-400')
  })

  it('statusBadgeClass returns gray for unknown status', () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusBadgeClass(99)).toBe('bg-gray-500/15 text-gray-400')
  })

  it('scoreBadgeClass returns red for score >= 80', () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).scoreBadgeClass(80)).toBe('text-red-400')
    expect((wrapper.vm as any).scoreBadgeClass(100)).toBe('text-red-400')
  })

  it('scoreBadgeClass returns orange for score 60-79', () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).scoreBadgeClass(60)).toBe('text-orange-400')
    expect((wrapper.vm as any).scoreBadgeClass(79)).toBe('text-orange-400')
  })

  it('scoreBadgeClass returns yellow for score 40-59', () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).scoreBadgeClass(40)).toBe('text-yellow-400')
    expect((wrapper.vm as any).scoreBadgeClass(59)).toBe('text-yellow-400')
  })

  it('scoreBadgeClass returns muted for score < 40', () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).scoreBadgeClass(39)).toBe('text-s1-muted')
    expect((wrapper.vm as any).scoreBadgeClass(0)).toBe('text-s1-muted')
  })

  it('fetchIncidents with append=false resets incidents when IDs are empty', async () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    expect(vm.incidents.length).toBe(1)
    mockQueryIds.mockResolvedValueOnce({
      resources: [],
      meta: { pagination: { total: 0 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    await vm.fetchIncidents()
    await flushPromises()
    expect(vm.incidents.length).toBe(0)
  })

  it('fetchIncidents(true) appends incidents to existing list', async () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    const initialCount = vm.incidents.length
    mockQueryIds.mockResolvedValueOnce({
      resources: ['inc-id-2'],
      meta: { pagination: { total: 5 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    mockGetEntities.mockResolvedValueOnce({
      resources: [
        { incident_id: 'inc-id-2', name: 'Beta Incident', status: 40, fine_score: 20, hosts: [], tactics: [], created: '2025-02-01T00:00:00Z' },
      ],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    await vm.fetchIncidents(true)
    await flushPromises()
    expect(vm.incidents.length).toBe(initialCount + 1)
  })

  it('hasMore is true when offset < total', async () => {
    mockQueryIds.mockResolvedValue({
      resources: ['inc-id-1'],
      meta: { pagination: { total: 100 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).hasMore).toBe(true)
  })

  it('hasMore is false when offset equals total', async () => {
    mockQueryIds.mockResolvedValue({
      resources: ['inc-id-1'],
      meta: { pagination: { total: 1 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).hasMore).toBe(false)
  })

  it('fetchIncidents builds filter when filterStatus is set', async () => {
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.filterStatus = '20'
    vi.clearAllMocks()
    await vm.fetchIncidents()
    await flushPromises()
    expect(csIncidentsApi.queryIds).toHaveBeenCalledWith(
      expect.objectContaining({ filter: 'status:20' }),
    )
  })

  it('total shows count of incidents from pagination', async () => {
    mockQueryIds.mockResolvedValue({
      resources: ['inc-id-1'],
      meta: { pagination: { total: 42 }, query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    const wrapper = mount(CsIncidentsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('42')
  })
})
