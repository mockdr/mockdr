import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

const FULL_ES_RULE_FIELDS = vi.hoisted(() => ({ rule_id: 'rule-x', created_at: '2025-01-01T00:00:00Z', updated_at: '2025-01-01T00:00:00Z', created_by: 'elastic', interval: '5m' }))

vi.mock('../../../api/elastic', () => ({
  esRulesApi: {
    find: vi.fn().mockResolvedValue({
      page: 1, per_page: 25,
      data: [
        {
          id: 'rule-1',
          name: 'Brute Force Login',
          description: 'Detects brute force attacks',
          severity: 'high',
          risk_score: 75,
          enabled: true,
          type: 'query',
          tags: ['auth', 'brute-force'],
          ...FULL_ES_RULE_FIELDS,
        },
        {
          id: 'rule-2',
          name: 'Malware Execution',
          description: 'Detects malware execution',
          severity: 'critical',
          risk_score: 95,
          enabled: false,
          type: 'eql',
          tags: ['malware'],
          ...FULL_ES_RULE_FIELDS,
        },
        {
          id: 'rule-3',
          name: 'Data Exfiltration',
          description: 'Detects data exfil',
          severity: 'medium',
          risk_score: 55,
          enabled: true,
          type: 'threshold',
          tags: ['exfil', 'network', 'data'],
          ...FULL_ES_RULE_FIELDS,
        },
        {
          id: 'rule-4',
          name: 'Low Signal',
          description: 'Low signal rule',
          severity: 'low',
          risk_score: 20,
          enabled: true,
          type: 'machine_learning',
          tags: null,
          ...FULL_ES_RULE_FIELDS,
        },
      ],
      total: 4,
    }),
    create: vi.fn().mockResolvedValue({ id: 'rule-new' }),
    delete: vi.fn().mockResolvedValue(undefined),
    bulkAction: vi.fn().mockResolvedValue({ attributes: { results: { updated: [], skipped: [], created: [] } } }),
  },
}))

import EsRulesView from '@/views/elastic/EsRulesView.vue'
import { esRulesApi } from '@/api/elastic'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/elastic/rules/:id', component: { template: '<div />' } },
  ],
})

const STUBS = {
  LoadingSkeleton: true,
  EmptyState: true,
  StatusBadge: true,
  RouterLink: { template: '<a><slot /></a>' },
  Teleport: true,
}

describe('EsRulesView', () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    await router.push('/')
    await router.isReady()
  })

  it('renders the page header with Detection Rules title', async () => {
    const wrapper = mount(EsRulesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Detection Rules')
  })

  it('calls fetchRules on mount', async () => {
    mount(EsRulesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(esRulesApi.find).toHaveBeenCalledWith(
      expect.objectContaining({ page: 1, per_page: 25 })
    )
  })

  it('displays loaded rules in the table', async () => {
    const wrapper = mount(EsRulesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Brute Force Login')
    expect(wrapper.text()).toContain('Malware Execution')
  })

  it('displays total rule count', async () => {
    const wrapper = mount(EsRulesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('4')
  })

  // severityBadgeClass function coverage - all branches
  it('severityBadgeClass returns correct class for critical', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { severityBadgeClass: (s: string) => string }
    expect(vm.severityBadgeClass('critical')).toBe('bg-red-500/15 text-red-400')
  })

  it('severityBadgeClass returns correct class for high', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { severityBadgeClass: (s: string) => string }
    expect(vm.severityBadgeClass('high')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('severityBadgeClass returns correct class for medium', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { severityBadgeClass: (s: string) => string }
    expect(vm.severityBadgeClass('medium')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('severityBadgeClass returns correct class for low', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { severityBadgeClass: (s: string) => string }
    expect(vm.severityBadgeClass('low')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('severityBadgeClass returns default class for unknown severity', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { severityBadgeClass: (s: string) => string }
    expect(vm.severityBadgeClass('unknown')).toBe('bg-gray-500/15 text-gray-400')
  })

  // fetchRules with filters
  it('fetchRules applies severity filter when set', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      filterSeverity: string
      fetchRules: (p?: number) => Promise<void>
    }
    vi.mocked(esRulesApi.find).mockClear()
    vm.filterSeverity = 'high'
    await vm.fetchRules()
    await flushPromises()
    expect(esRulesApi.find).toHaveBeenCalledWith(
      expect.objectContaining({
        filter: expect.stringContaining('high'),
      })
    )
  })

  it('fetchRules applies enabled filter when set', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      filterEnabled: string
      fetchRules: (p?: number) => Promise<void>
    }
    vi.mocked(esRulesApi.find).mockClear()
    vm.filterEnabled = 'true'
    await vm.fetchRules()
    await flushPromises()
    expect(esRulesApi.find).toHaveBeenCalledWith(
      expect.objectContaining({
        filter: expect.stringContaining('true'),
      })
    )
  })

  it('fetchRules combines multiple filters with AND', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      filterSeverity: string
      filterEnabled: string
      fetchRules: (p?: number) => Promise<void>
    }
    vm.filterSeverity = 'high'
    vm.filterEnabled = 'true'
    vi.mocked(esRulesApi.find).mockClear()
    await vm.fetchRules()
    await flushPromises()
    const callArg = vi.mocked(esRulesApi.find).mock.calls[0][0] as Record<string, unknown>
    expect(callArg['filter']).toContain(' AND ')
  })

  // createRule function
  it('createRule calls esRulesApi.create and refreshes', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      showCreateDialog: boolean
      newRule: { name: string; description: string; severity: string; risk_score: number; type: string; enabled: boolean }
      createRule: () => Promise<void>
    }
    vm.showCreateDialog = true
    vm.newRule.name = 'New Detection Rule'
    vm.newRule.description = 'Detects new threat'
    vm.newRule.severity = 'high'
    vm.newRule.risk_score = 80
    vi.mocked(esRulesApi.find).mockClear()
    await vm.createRule()
    await flushPromises()
    expect(esRulesApi.create).toHaveBeenCalledWith(
      expect.objectContaining({ name: 'New Detection Rule', severity: 'high' })
    )
    expect(esRulesApi.find).toHaveBeenCalled()
    expect(vm.showCreateDialog).toBe(false)
  })

  it('createRule resets newRule after success', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      newRule: { name: string; description: string; severity: string; risk_score: number; type: string; enabled: boolean }
      createRule: () => Promise<void>
    }
    vm.newRule.name = 'Temp Rule'
    await vm.createRule()
    await flushPromises()
    expect(vm.newRule.name).toBe('')
    expect(vm.newRule.severity).toBe('medium')
    expect(vm.newRule.risk_score).toBe(50)
  })

  // deleteRule function
  it('deleteRule calls esRulesApi.delete and refreshes', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { deleteRule: (id: string) => Promise<void> }
    vi.mocked(esRulesApi.find).mockClear()
    await vm.deleteRule('rule-1')
    await flushPromises()
    expect(esRulesApi.delete).toHaveBeenCalledWith('rule-1')
    expect(esRulesApi.find).toHaveBeenCalled()
  })

  // toggleEnabled function - disable path (rule currently enabled)
  it('toggleEnabled calls bulkAction with disable when rule is enabled', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { toggleEnabled: (rule: { id: string; enabled: boolean }) => Promise<void> }
    const rule = { id: 'rule-1', enabled: true }
    await vm.toggleEnabled(rule)
    await flushPromises()
    expect(esRulesApi.bulkAction).toHaveBeenCalledWith({
      action: 'disable',
      ids: ['rule-1'],
    })
    expect(rule.enabled).toBe(false)
  })

  // toggleEnabled function - enable path (rule currently disabled)
  it('toggleEnabled calls bulkAction with enable when rule is disabled', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { toggleEnabled: (rule: { id: string; enabled: boolean }) => Promise<void> }
    const rule = { id: 'rule-2', enabled: false }
    await vm.toggleEnabled(rule)
    await flushPromises()
    expect(esRulesApi.bulkAction).toHaveBeenCalledWith({
      action: 'enable',
      ids: ['rule-2'],
    })
    expect(rule.enabled).toBe(true)
  })

  it('toggleEnabled refetches rules on error', async () => {
    vi.mocked(esRulesApi.bulkAction).mockRejectedValueOnce(new Error('toggle failed'))
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { toggleEnabled: (rule: { id: string; enabled: boolean }) => Promise<void> }
    vi.mocked(esRulesApi.find).mockClear()
    await vm.toggleEnabled({ id: 'rule-1', enabled: true })
    await flushPromises()
    expect(esRulesApi.find).toHaveBeenCalled()
  })

  // bulkEnable function - no selection
  it('bulkEnable does nothing when nothing is selected', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esRulesApi.bulkAction).mockClear()
    const vm = wrapper.vm as unknown as { bulkEnable: (enable: boolean) => Promise<void> }
    await vm.bulkEnable(true)
    await flushPromises()
    expect(esRulesApi.bulkAction).not.toHaveBeenCalled()
  })

  // bulkEnable - enable selected rules
  it('bulkEnable enables selected rules', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      selected: Set<string>
      bulkEnable: (enable: boolean) => Promise<void>
    }
    vm.selected.add('rule-1')
    vm.selected.add('rule-2')
    await vm.bulkEnable(true)
    await flushPromises()
    expect(esRulesApi.bulkAction).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'enable' })
    )
    expect(vm.selected.size).toBe(0)
  })

  // bulkEnable - disable selected rules
  it('bulkEnable disables selected rules', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      selected: Set<string>
      bulkEnable: (enable: boolean) => Promise<void>
    }
    vm.selected.add('rule-1')
    await vm.bulkEnable(false)
    await flushPromises()
    expect(esRulesApi.bulkAction).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'disable' })
    )
  })

  // hasPrev computed
  it('hasPrev is false on page 1', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { hasPrev: boolean }
    expect(vm.hasPrev).toBe(false)
  })

  it('hasPrev is true on page 2', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { hasPrev: boolean; fetchRules: (p: number) => Promise<void> }
    await vm.fetchRules(2)
    expect(vm.hasPrev).toBe(true)
  })

  // hasNext computed
  it('hasNext is false when total fits on one page', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { hasNext: boolean }
    expect(vm.hasNext).toBe(false)
  })

  it('hasNext is true when total exceeds current page', async () => {
    vi.mocked(esRulesApi.find).mockResolvedValueOnce({
      page: 1, per_page: 25,
      data: [{ id: 'r1', name: 'Rule 1', severity: 'low', risk_score: 10, enabled: true, type: 'query', tags: [], description: '', ...FULL_ES_RULE_FIELDS }],
      total: 100,
    })
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { hasNext: boolean }
    expect(vm.hasNext).toBe(true)
  })

  // Error handling
  it('sets loading to false when fetchRules throws', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esRulesApi.find).mockRejectedValueOnce(new Error('API error'))
    const vm = wrapper.vm as unknown as { loading: boolean; fetchRules: () => Promise<void> }
    try { await vm.fetchRules() } catch { /* expected */ }
    await flushPromises()
    expect(vm.loading).toBe(false)
  })

  it('sets loading to false when deleteRule throws', async () => {
    vi.mocked(esRulesApi.delete).mockRejectedValueOnce(new Error('delete failed'))
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { loading: boolean; deleteRule: (id: string) => Promise<void> }
    try {
      await vm.deleteRule('rule-1')
    } catch {
      // expected
    }
    await flushPromises()
    expect(vm.loading).toBe(false)
  })

  // Watch triggers fetchRules when filterSeverity changes
  it('watch on filterSeverity triggers fetchRules', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esRulesApi.find).mockClear()
    const vm = wrapper.vm as unknown as { filterSeverity: string }
    vm.filterSeverity = 'medium'
    await flushPromises()
    expect(esRulesApi.find).toHaveBeenCalled()
  })

  // Watch triggers fetchRules when filterEnabled changes
  it('watch on filterEnabled triggers fetchRules', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esRulesApi.find).mockClear()
    const vm = wrapper.vm as unknown as { filterEnabled: string }
    vm.filterEnabled = 'false'
    await flushPromises()
    expect(esRulesApi.find).toHaveBeenCalled()
  })

  // Open create dialog
  it('opens create dialog on Create Rule button click', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const btn = wrapper.findAll('button').find(b => b.text().includes('Create Rule'))
    expect(btn).toBeDefined()
    await btn!.trigger('click')
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Create Detection Rule')
  })

  // Empty state
  it('shows empty state when no rules are returned', async () => {
    vi.mocked(esRulesApi.find).mockResolvedValueOnce({ page: 1, per_page: 25, data: [], total: 0 })
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.html()).toContain('empty-state-stub')
  })

  it('Refresh button calls fetchRules via DOM click', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esRulesApi.find).mockClear()
    const btn = wrapper.findAll('button').find(b => b.text().includes('Refresh'))
    await btn!.trigger('click')
    await flushPromises()
    expect(esRulesApi.find).toHaveBeenCalled()
  })

  it('header checkbox change selects all rows via DOM', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const headerCheckbox = wrapper.find('thead input[type="checkbox"]')
    await headerCheckbox.trigger('change')
    const vm = wrapper.vm as unknown as { selected: Set<string> }
    expect(vm.selected.size).toBeGreaterThan(0)
  })

  it('row checkbox change toggles selection via DOM', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const rowCheckboxes = wrapper.findAll('tbody input[type="checkbox"]')
    await rowCheckboxes[0].trigger('change')
    const vm = wrapper.vm as unknown as { selected: Set<string> }
    expect(vm.selected.has('rule-1')).toBe(true)
  })

  it('toggle button calls toggleEnabled via DOM click', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esRulesApi.bulkAction).mockClear()
    // The toggle buttons are inside td @click.stop cells
    const toggleBtn = wrapper.find('td button.relative.inline-flex')
    await toggleBtn.trigger('click')
    await flushPromises()
    expect(esRulesApi.bulkAction).toHaveBeenCalled()
  })

  it('delete button calls deleteRule via DOM click', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esRulesApi.find).mockClear()
    const deleteBtn = wrapper.find('button.btn-ghost.text-red-400')
    await deleteBtn.trigger('click')
    await flushPromises()
    expect(esRulesApi.delete).toHaveBeenCalled()
  })

  it('Previous button calls fetchRules(page-1) via DOM click', async () => {
    vi.mocked(esRulesApi.find).mockResolvedValue({
      page: 1, per_page: 25,
      data: [{ id: 'r1', name: 'Rule', severity: 'low', risk_score: 10, enabled: true, type: 'query', tags: [], description: '', ...FULL_ES_RULE_FIELDS }],
      total: 100,
    })
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    // Navigate to page 2 first
    const vm = wrapper.vm as unknown as { fetchRules: (p: number) => Promise<void> }
    await vm.fetchRules(2)
    await flushPromises()
    vi.mocked(esRulesApi.find).mockClear()
    const prevBtn = wrapper.findAll('button').find(b => b.text() === 'Previous')
    await prevBtn!.trigger('click')
    await flushPromises()
    expect(esRulesApi.find).toHaveBeenCalledWith(expect.objectContaining({ page: 1 }))
  })

  it('Next button calls fetchRules(page+1) via DOM click', async () => {
    vi.mocked(esRulesApi.find).mockResolvedValue({
      page: 1, per_page: 25,
      data: [{ id: 'r1', name: 'Rule', severity: 'low', risk_score: 10, enabled: true, type: 'query', tags: [], description: '', ...FULL_ES_RULE_FIELDS }],
      total: 100,
    })
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esRulesApi.find).mockClear()
    const nextBtn = wrapper.findAll('button').find(b => b.text() === 'Next')
    await nextBtn!.trigger('click')
    await flushPromises()
    expect(esRulesApi.find).toHaveBeenCalledWith(expect.objectContaining({ page: 2 }))
  })

  it('Create button in dialog calls createRule via DOM click', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { showCreateDialog: boolean; newRule: { name: string } }
    vm.showCreateDialog = true
    vm.newRule.name = 'DOM Created Rule'
    await wrapper.vm.$nextTick()
    const createBtn = wrapper.findAll('button').find(b => b.text() === 'Create')
    await createBtn!.trigger('click')
    await flushPromises()
    expect(esRulesApi.create).toHaveBeenCalled()
  })

  it('Cancel button in create dialog closes it via DOM click', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { showCreateDialog: boolean }
    vm.showCreateDialog = true
    await wrapper.vm.$nextTick()
    const cancelBtn = wrapper.findAll('button').find(b => b.text() === 'Cancel')
    await cancelBtn!.trigger('click')
    expect(vm.showCreateDialog).toBe(false)
  })

  it('Enable All button calls bulkEnable(true) via DOM click', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { selected: Set<string> }
    vm.selected.add('rule-1')
    await wrapper.vm.$nextTick()
    vi.mocked(esRulesApi.bulkAction).mockClear()
    const enableBtn = wrapper.findAll('button').find(b => b.text().includes('Enable All'))
    await enableBtn!.trigger('click')
    await flushPromises()
    expect(esRulesApi.bulkAction).toHaveBeenCalledWith(expect.objectContaining({ action: 'enable' }))
  })

  it('Disable All button calls bulkEnable(false) via DOM click', async () => {
    const wrapper = mount(EsRulesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { selected: Set<string> }
    vm.selected.add('rule-1')
    await wrapper.vm.$nextTick()
    vi.mocked(esRulesApi.bulkAction).mockClear()
    const disableBtn = wrapper.findAll('button').find(b => b.text().includes('Disable All'))
    await disableBtn!.trigger('click')
    await flushPromises()
    expect(esRulesApi.bulkAction).toHaveBeenCalledWith(expect.objectContaining({ action: 'disable' }))
  })
})
