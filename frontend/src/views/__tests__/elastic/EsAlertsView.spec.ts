import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/elastic', () => ({
  esAlertsApi: {
    search: vi.fn().mockResolvedValue({
      took: 5,
      hits: {
        hits: [
          {
            _id: 'alert-1',
            _index: '.alerts-security',
            _source: {
              id: 'alert-1',
              rule_name: 'Brute Force Detected',
              severity: 'high',
              risk_score: 70,
              status: 'open',
              host_name: 'WKSTN-001',
              timestamp: '2025-01-01T00:00:00Z',
              rule_id: 'rule-1',
            },
          },
          {
            _id: 'alert-2',
            _index: '.alerts-security',
            _source: {
              id: 'alert-2',
              rule_name: 'Malware Execution',
              severity: 'critical',
              risk_score: 95,
              status: 'acknowledged',
              host_name: 'SERVER-001',
              timestamp: '2025-01-02T00:00:00Z',
              rule_id: 'rule-2',
            },
          },
        ],
        total: { value: 2, relation: 'eq' },
      },
    }),
    updateStatus: vi.fn().mockResolvedValue({}),
  },
}))

vi.mock('../../../utils/formatters', () => ({
  relativeTime: vi.fn().mockReturnValue('2 hours ago'),
}))

import EsAlertsView from '@/views/elastic/EsAlertsView.vue'
import { esAlertsApi } from '@/api/elastic'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/elastic/alerts', component: { template: '<div />' } },
  ],
})

const STUBS = {
  LoadingSkeleton: true,
  EmptyState: true,
  RouterLink: { template: '<a><slot /></a>' },
  Teleport: true,
}

describe('EsAlertsView', () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    await router.push('/')
    await router.isReady()
  })

  it('renders the page header with Alerts title', async () => {
    const wrapper = mount(EsAlertsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Alerts')
  })

  it('calls esAlertsApi.search on mount', async () => {
    mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(esAlertsApi.search).toHaveBeenCalled()
  })

  it('displays loaded alert rule names after mount', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('Brute Force Detected')
    expect(wrapper.text()).toContain('Malware Execution')
  })

  it('displays total alert count', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('2')
  })

  // severityBadgeClass — all branches
  it('severityBadgeClass returns red for critical', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('critical')).toBe('bg-red-500/15 text-red-400')
  })

  it('severityBadgeClass returns orange for high', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('high')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('severityBadgeClass returns yellow for medium', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('medium')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('severityBadgeClass returns blue for low', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('low')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('severityBadgeClass returns gray for unknown severity', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('unknown')).toBe('bg-gray-500/15 text-gray-400')
  })

  // statusBadgeClass — all branches
  it('statusBadgeClass returns blue for open', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('open')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('statusBadgeClass returns yellow for in-progress', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('in-progress')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('statusBadgeClass returns yellow for acknowledged', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('acknowledged')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('statusBadgeClass returns green for closed', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('closed')).toBe('bg-green-500/15 text-green-400')
  })

  it('statusBadgeClass returns gray for unknown status', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('something')).toBe('bg-gray-500/15 text-gray-400')
  })

  // fetchAlerts — direction: reset (default)
  it('fetchAlerts with reset direction resets from to 0', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.from = 50
    vi.mocked(esAlertsApi.search).mockClear()
    await vm.fetchAlerts('reset')
    await flushPromises()
    expect(vm.from).toBe(0)
    expect(esAlertsApi.search).toHaveBeenCalled()
  })

  // fetchAlerts — direction: next
  it('fetchAlerts with next direction increments from by size', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    // Set total > size so next is valid
    vm.total = 100
    const prevFrom = vm.from
    await vm.fetchAlerts('next')
    await flushPromises()
    expect(vm.from).toBe(prevFrom + 25)
  })

  // fetchAlerts — direction: prev
  it('fetchAlerts with prev direction decrements from by size', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.from = 50
    await vm.fetchAlerts('prev')
    await flushPromises()
    expect(vm.from).toBe(25)
  })

  it('fetchAlerts with prev direction clamps to 0 when from < size', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.from = 10
    await vm.fetchAlerts('prev')
    await flushPromises()
    expect(vm.from).toBe(0)
  })

  // fetchAlerts applies severity filter
  it('fetchAlerts includes severity filter in query body when set', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.filterSeverity = 'critical'
    vi.mocked(esAlertsApi.search).mockClear()
    await vm.fetchAlerts()
    await flushPromises()
    const body = vi.mocked(esAlertsApi.search).mock.calls[0][0] as Record<string, unknown>
    expect(JSON.stringify(body)).toContain('critical')
  })

  // fetchAlerts applies status filter
  it('fetchAlerts includes status filter in query body when set', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.filterStatus = 'closed'
    vi.mocked(esAlertsApi.search).mockClear()
    await vm.fetchAlerts()
    await flushPromises()
    const body = vi.mocked(esAlertsApi.search).mock.calls[0][0] as Record<string, unknown>
    expect(JSON.stringify(body)).toContain('closed')
  })

  it('fetchAlerts uses match_all when no filters set', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.filterSeverity = ''
    vm.filterStatus = ''
    vi.mocked(esAlertsApi.search).mockClear()
    await vm.fetchAlerts()
    await flushPromises()
    const body = vi.mocked(esAlertsApi.search).mock.calls[0][0] as Record<string, unknown>
    expect(JSON.stringify(body)).toContain('match_all')
  })

  it('fetchAlerts sets loading to false after success', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    await (wrapper.vm as any).fetchAlerts()
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('fetchAlerts sets loading to false on error', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esAlertsApi.search).mockRejectedValueOnce(new Error('API error'))
    try { await (wrapper.vm as any).fetchAlerts() } catch { /* expected */ }
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  // hasPrev / hasNext computeds
  it('hasPrev is false when from is 0', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).hasPrev).toBe(false)
  })

  it('hasPrev is true when from is greater than 0', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).from = 25
    expect((wrapper.vm as any).hasPrev).toBe(true)
  })

  it('hasNext is false when total fits in current window', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    // from=0, total=2, size=25: 0+25 < 2 is false
    expect((wrapper.vm as any).hasNext).toBe(false)
  })

  it('hasNext is true when more pages exist', async () => {
    vi.mocked(esAlertsApi.search).mockResolvedValueOnce({
      took: 1,
      hits: {
        hits: [{ _id: 'a1', _index: '.alerts-security', _source: { id: 'a1', rule_name: 'R1', severity: 'low', risk_score: 30, status: 'open', host_name: 'H1', timestamp: '2025-01-01T00:00:00Z', rule_id: 'rule-x' } }],
        total: { value: 100, relation: 'eq' },
      },
    })
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).hasNext).toBe(true)
  })

  // bulkUpdateStatus — empty guard
  it('bulkUpdateStatus does nothing when nothing is selected', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esAlertsApi.updateStatus).mockClear()
    await (wrapper.vm as any).bulkUpdateStatus('closed')
    await flushPromises()
    expect(esAlertsApi.updateStatus).not.toHaveBeenCalled()
  })

  // bulkUpdateStatus — acknowledge
  it('bulkUpdateStatus calls updateStatus with selected ids and new status', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.selected.add('alert-1')
    vm.selected.add('alert-2')
    await vm.bulkUpdateStatus('acknowledged')
    await flushPromises()
    expect(esAlertsApi.updateStatus).toHaveBeenCalledWith({
      signal_ids: expect.arrayContaining(['alert-1', 'alert-2']),
      status: 'acknowledged',
    })
  })

  // bulkUpdateStatus — close
  it('bulkUpdateStatus can set status to closed', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.selected.add('alert-1')
    await vm.bulkUpdateStatus('closed')
    await flushPromises()
    expect(esAlertsApi.updateStatus).toHaveBeenCalledWith(
      expect.objectContaining({ status: 'closed' })
    )
  })

  // bulkUpdateStatus — reopen
  it('bulkUpdateStatus can set status to open (reopen)', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.selected.add('alert-1')
    await vm.bulkUpdateStatus('open')
    await flushPromises()
    expect(esAlertsApi.updateStatus).toHaveBeenCalledWith(
      expect.objectContaining({ status: 'open' })
    )
  })

  it('bulkUpdateStatus clears selection after success', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.selected.add('alert-1')
    await vm.bulkUpdateStatus('closed')
    await flushPromises()
    expect(vm.selected.size).toBe(0)
  })

  it('bulkUpdateStatus refreshes alerts after success', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.selected.add('alert-1')
    vi.mocked(esAlertsApi.search).mockClear()
    await vm.bulkUpdateStatus('closed')
    await flushPromises()
    expect(esAlertsApi.search).toHaveBeenCalled()
  })

  it('bulkUpdateStatus sets loading to false on error', async () => {
    vi.mocked(esAlertsApi.updateStatus).mockRejectedValueOnce(new Error('update failed'))
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.selected.add('alert-1')
    try { await vm.bulkUpdateStatus('closed') } catch { /* expected */ }
    await flushPromises()
    expect(vm.loading).toBe(false)
  })

  // Watch triggers re-fetch when filters change
  it('watch on filterSeverity triggers fetchAlerts', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esAlertsApi.search).mockClear()
    ;(wrapper.vm as any).filterSeverity = 'high'
    await flushPromises()
    expect(esAlertsApi.search).toHaveBeenCalled()
  })

  it('watch on filterStatus triggers fetchAlerts', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esAlertsApi.search).mockClear()
    ;(wrapper.vm as any).filterStatus = 'closed'
    await flushPromises()
    expect(esAlertsApi.search).toHaveBeenCalled()
  })

  it('shows empty state when no alerts are returned', async () => {
    vi.mocked(esAlertsApi.search).mockResolvedValueOnce({
      took: 1,
      hits: { hits: [], total: { value: 0, relation: 'eq' } },
    })
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.html()).toContain('empty-state-stub')
  })

  it('Refresh button calls fetchAlerts via DOM click', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esAlertsApi.search).mockClear()
    const btn = wrapper.findAll('button').find(b => b.text().includes('Refresh'))
    await btn!.trigger('click')
    await flushPromises()
    expect(esAlertsApi.search).toHaveBeenCalled()
  })

  it('header checkbox selects all alerts via DOM change', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const headerCheckbox = wrapper.find('thead input[type="checkbox"]')
    await headerCheckbox.trigger('change')
    const vm = wrapper.vm as any
    expect(vm.selected.size).toBeGreaterThan(0)
  })

  it('row checkbox toggles individual alert selection via DOM change', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const rowCheckboxes = wrapper.findAll('tbody input[type="checkbox"]')
    await rowCheckboxes[0].trigger('change')
    const vm = wrapper.vm as any
    expect(vm.selected.has('alert-1')).toBe(true)
  })

  it('Acknowledge button calls bulkUpdateStatus via DOM click', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.selected.add('alert-1')
    await wrapper.vm.$nextTick()
    vi.mocked(esAlertsApi.updateStatus).mockClear()
    const btn = wrapper.findAll('button').find(b => b.text() === 'Acknowledge')
    await btn!.trigger('click')
    await flushPromises()
    expect(esAlertsApi.updateStatus).toHaveBeenCalledWith(expect.objectContaining({ status: 'acknowledged' }))
  })

  it('Close button calls bulkUpdateStatus via DOM click', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.selected.add('alert-1')
    await wrapper.vm.$nextTick()
    vi.mocked(esAlertsApi.updateStatus).mockClear()
    const btn = wrapper.findAll('button').find(b => b.text() === 'Close')
    await btn!.trigger('click')
    await flushPromises()
    expect(esAlertsApi.updateStatus).toHaveBeenCalledWith(expect.objectContaining({ status: 'closed' }))
  })

  it('Reopen button calls bulkUpdateStatus via DOM click', async () => {
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.selected.add('alert-1')
    await wrapper.vm.$nextTick()
    vi.mocked(esAlertsApi.updateStatus).mockClear()
    const btn = wrapper.findAll('button').find(b => b.text() === 'Reopen')
    await btn!.trigger('click')
    await flushPromises()
    expect(esAlertsApi.updateStatus).toHaveBeenCalledWith(expect.objectContaining({ status: 'open' }))
  })

  it('Previous button calls fetchAlerts(prev) via DOM click', async () => {
    vi.mocked(esAlertsApi.search).mockResolvedValue({
      took: 1,
      hits: {
        hits: [{ _id: 'a1', _index: '.alerts-security', _source: { id: 'a1', rule_name: 'R1', severity: 'low', risk_score: 30, status: 'open', host_name: 'H1', timestamp: '2025-01-01T00:00:00Z', rule_id: 'rule-x' } }],
        total: { value: 100, relation: 'eq' },
      },
    })
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    // Set from > 0 so prev is enabled
    vm.from = 25
    await wrapper.vm.$nextTick()
    vi.mocked(esAlertsApi.search).mockClear()
    const prevBtn = wrapper.findAll('button').find(b => b.text() === 'Previous')
    await prevBtn!.trigger('click')
    await flushPromises()
    expect(vm.from).toBe(0)
  })

  it('Next button calls fetchAlerts(next) via DOM click', async () => {
    vi.mocked(esAlertsApi.search).mockResolvedValue({
      took: 1,
      hits: {
        hits: [{ _id: 'a1', _index: '.alerts-security', _source: { id: 'a1', rule_name: 'R1', severity: 'low', risk_score: 30, status: 'open', host_name: 'H1', timestamp: '2025-01-01T00:00:00Z', rule_id: 'rule-x' } }],
        total: { value: 100, relation: 'eq' },
      },
    })
    const wrapper = mount(EsAlertsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vi.mocked(esAlertsApi.search).mockClear()
    const nextBtn = wrapper.findAll('button').find(b => b.text() === 'Next')
    await nextBtn!.trigger('click')
    await flushPromises()
    expect(vm.from).toBe(25)
  })
})
