import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/cortex', () => ({
  xdrIncidentsApi: {
    list: vi.fn().mockResolvedValue({
      reply: {
        total_count: 3,
        result_count: 3,
        incidents: [
          {
            incident_id: 'inc-001',
            description: 'Malware detected on workstation',
            status: 'new',
            severity: 'critical',
            creation_time: 1700000000000,
            modification_time: 1700000100000,
            alert_count: 5,
            assigned_user_pretty_name: 'Alice Smith',
            assigned_user_mail: 'alice@corp.com',
            hosts: ['WKSTN-001'],
            users: ['alice'],
            rule_based_score: 90,
          },
          {
            incident_id: 'inc-002',
            description: 'Suspicious network activity',
            status: 'under_investigation',
            severity: 'high',
            creation_time: 1700001000000,
            modification_time: 1700001100000,
            alert_count: 2,
            assigned_user_pretty_name: '',
            assigned_user_mail: 'bob@corp.com',
            hosts: [],
            users: [],
            rule_based_score: 65,
          },
          {
            incident_id: 'inc-003',
            description: 'Phishing attempt',
            status: 'resolved_true_positive',
            severity: 'medium',
            creation_time: 1700002000000,
            modification_time: 1700002100000,
            alert_count: 1,
            assigned_user_pretty_name: null,
            assigned_user_mail: null,
            hosts: [],
            users: [],
            rule_based_score: 40,
          },
        ],
      },
    }),
  },
}))

vi.mock('../../../utils/formatters', () => ({
  formatEpoch: vi.fn(() => '2024-11-14 22:13:20'),
  relativeTime: vi.fn((v: string) => v),
}))

import XdrIncidentsView from '@/views/xdr/XdrIncidentsView.vue'

const STUBS = {
  LoadingSkeleton: true,
  EmptyState: true,
  StatusBadge: true,
  RouterLink: { template: '<a><slot /></a>' },
  Teleport: true,
}

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/cortex-xdr/incidents/:id', component: { template: '<div />' } },
  ],
})

function mountView() {
  return mount(XdrIncidentsView, {
    global: { plugins: [router], stubs: STUBS },
  })
}

describe('XdrIncidentsView', () => {
  beforeEach(async () => {
    await router.push('/')
    await router.isReady()
    vi.clearAllMocks()
  })

  it('renders the page header with XDR and Incidents text', () => {
    const wrapper = mountView()
    expect(wrapper.text()).toContain('XDR')
    expect(wrapper.text()).toContain('Incidents')
  })

  it('renders the filter selects', () => {
    const wrapper = mountView()
    const selects = wrapper.findAll('select')
    expect(selects.length).toBeGreaterThanOrEqual(2)
  })

  it('fetches and displays incidents on mount', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('inc-001')
    expect(wrapper.text()).toContain('Malware detected on workstation')
  })

  it('displays all three incidents after load', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('inc-001')
    expect(wrapper.text()).toContain('inc-002')
    expect(wrapper.text()).toContain('inc-003')
  })

  it('shows assigned user pretty name when available', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Alice Smith')
  })

  it('shows assigned user email as fallback', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('bob@corp.com')
  })

  it('calls fetchIncidents again when Refresh button is clicked', async () => {
    const { xdrIncidentsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const refreshBtn = wrapper.find('button')
    await refreshBtn.trigger('click')
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(xdrIncidentsApi.list).toHaveBeenCalledTimes(2)
  })

  it('calls fetchIncidents via wrapper.vm', async () => {
    const { xdrIncidentsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    await (wrapper.vm as any).fetchIncidents()
    expect(xdrIncidentsApi.list).toHaveBeenCalledTimes(2)
  })

  it('severityBadgeClass returns correct class for critical', async () => {
    const wrapper = mountView()
    await flushPromises()
    const result = (wrapper.vm as any).severityBadgeClass('critical')
    expect(result).toBe('bg-red-500/15 text-red-400')
  })

  it('severityBadgeClass returns correct class for high', async () => {
    const wrapper = mountView()
    await flushPromises()
    const result = (wrapper.vm as any).severityBadgeClass('high')
    expect(result).toBe('bg-orange-500/15 text-orange-400')
  })

  it('severityBadgeClass returns correct class for medium', async () => {
    const wrapper = mountView()
    await flushPromises()
    const result = (wrapper.vm as any).severityBadgeClass('medium')
    expect(result).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('severityBadgeClass returns correct class for low', async () => {
    const wrapper = mountView()
    await flushPromises()
    const result = (wrapper.vm as any).severityBadgeClass('low')
    expect(result).toBe('bg-blue-500/15 text-blue-400')
  })

  it('severityBadgeClass returns default class for unknown', async () => {
    const wrapper = mountView()
    await flushPromises()
    const result = (wrapper.vm as any).severityBadgeClass('unknown')
    expect(result).toBe('bg-gray-500/15 text-gray-400')
  })

  it('severityBadgeClass handles null/undefined input', async () => {
    const wrapper = mountView()
    await flushPromises()
    const result = (wrapper.vm as any).severityBadgeClass(null)
    expect(result).toBe('bg-gray-500/15 text-gray-400')
  })

  it('statusBadgeClass returns correct class for new', async () => {
    const wrapper = mountView()
    await flushPromises()
    const result = (wrapper.vm as any).statusBadgeClass('new')
    expect(result).toBe('bg-blue-500/15 text-blue-400')
  })

  it('statusBadgeClass returns correct class for under_investigation', async () => {
    const wrapper = mountView()
    await flushPromises()
    const result = (wrapper.vm as any).statusBadgeClass('under_investigation')
    expect(result).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('statusBadgeClass returns correct class for resolved_true_positive', async () => {
    const wrapper = mountView()
    await flushPromises()
    const result = (wrapper.vm as any).statusBadgeClass('resolved_true_positive')
    expect(result).toBe('bg-green-500/15 text-green-400')
  })

  it('statusBadgeClass returns correct class for resolved_false_positive', async () => {
    const wrapper = mountView()
    await flushPromises()
    const result = (wrapper.vm as any).statusBadgeClass('resolved_false_positive')
    expect(result).toBe('bg-gray-500/15 text-gray-400')
  })

  it('statusBadgeClass returns correct class for resolved_known_issue', async () => {
    const wrapper = mountView()
    await flushPromises()
    const result = (wrapper.vm as any).statusBadgeClass('resolved_known_issue')
    expect(result).toBe('bg-teal-500/15 text-teal-400')
  })

  it('statusBadgeClass returns correct class for resolved_duplicate', async () => {
    const wrapper = mountView()
    await flushPromises()
    const result = (wrapper.vm as any).statusBadgeClass('resolved_duplicate')
    expect(result).toBe('bg-teal-500/15 text-teal-400')
  })

  it('statusBadgeClass returns correct class for resolved_other', async () => {
    const wrapper = mountView()
    await flushPromises()
    const result = (wrapper.vm as any).statusBadgeClass('resolved_other')
    expect(result).toBe('bg-teal-500/15 text-teal-400')
  })

  it('statusBadgeClass returns default class for unknown', async () => {
    const wrapper = mountView()
    await flushPromises()
    const result = (wrapper.vm as any).statusBadgeClass('unknown')
    expect(result).toBe('bg-gray-500/15 text-gray-400')
  })

  it('statusBadgeClass handles null/undefined input', async () => {
    const wrapper = mountView()
    await flushPromises()
    const result = (wrapper.vm as any).statusBadgeClass(null)
    expect(result).toBe('bg-gray-500/15 text-gray-400')
  })

  it('filters incidents by severity', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.filterSeverity = 'critical'
    await wrapper.vm.$nextTick()
    expect(vm.filteredIncidents.length).toBe(1)
    expect(vm.filteredIncidents[0].incident_id).toBe('inc-001')
  })

  it('filters incidents by status', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.filterStatus = 'new'
    await wrapper.vm.$nextTick()
    expect(vm.filteredIncidents.length).toBe(1)
    expect(vm.filteredIncidents[0].incident_id).toBe('inc-001')
  })

  it('combining severity and status filters narrows results', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.filterSeverity = 'high'
    vm.filterStatus = 'under_investigation'
    await wrapper.vm.$nextTick()
    expect(vm.filteredIncidents.length).toBe(1)
    expect(vm.filteredIncidents[0].incident_id).toBe('inc-002')
  })

  it('clearing filters shows all incidents', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.filterSeverity = 'high'
    await wrapper.vm.$nextTick()
    vm.filterSeverity = ''
    await wrapper.vm.$nextTick()
    expect(vm.filteredIncidents.length).toBe(3)
  })

  it('shows total count text', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('incidents')
  })

  it('shows severity badge classes in rendered output', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const html = wrapper.html()
    expect(html).toContain('bg-red-500/15')
  })
})
