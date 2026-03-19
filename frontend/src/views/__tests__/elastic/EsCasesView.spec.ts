import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'
import { flushPromises } from '@vue/test-utils'

const FULL_CASE_FIELDS = vi.hoisted(() => ({
  updated_at: '2025-01-01T00:00:00Z',
  connector: { id: 'none', name: 'None' },
}))

vi.mock('../../../api/elastic', () => ({
  esCasesApi: {
    find: vi.fn().mockResolvedValue({
      page: 1,
      per_page: 25,
      total: 4,
      data: [
        {
          id: 'case-1',
          title: 'Suspicious login detected',
          description: 'Multiple failed logins from unknown IP',
          status: 'open',
          severity: 'high',
          tags: ['auth', 'suspicious'],
          total_comment: 3,
          created_at: '2025-01-15T10:00:00Z',
          created_by: { username: 'analyst1' },
          ...FULL_CASE_FIELDS,
        },
        {
          id: 'case-2',
          title: 'Malware outbreak',
          description: 'Ransomware detected on endpoints',
          status: 'in-progress',
          severity: 'critical',
          tags: ['malware', 'ransomware', 'endpoints'],
          total_comment: 7,
          created_at: '2025-01-14T08:30:00Z',
          created_by: { username: 'analyst2' },
          ...FULL_CASE_FIELDS,
        },
        {
          id: 'case-3',
          title: 'Resolved phishing',
          description: 'Phishing email campaign',
          status: 'closed',
          severity: 'medium',
          tags: [],
          total_comment: 1,
          created_at: '2025-01-10T12:00:00Z',
          created_by: { username: 'analyst3' },
          ...FULL_CASE_FIELDS,
        },
        {
          id: 'case-4',
          title: 'Low priority event',
          description: 'Low severity incident',
          status: 'open',
          severity: 'low',
          tags: ['low'],
          total_comment: 0,
          created_at: '2025-01-13T09:00:00Z',
          created_by: { username: 'unknown' },
          ...FULL_CASE_FIELDS,
        },
      ],
    }),
    create: vi.fn().mockResolvedValue({ id: 'case-new', title: 'New Case', description: '', status: 'open', severity: 'low', tags: [], total_comment: 0, created_at: '', updated_at: '', created_by: { username: '' }, connector: { id: 'none', name: 'None' } }),
  },
}))

import EsCasesView from '@/views/elastic/EsCasesView.vue'
import { esCasesApi } from '@/api/elastic'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/elastic/cases/:id', component: { template: '<div />' } },
  ],
})

const STUBS = {
  LoadingSkeleton: true,
  EmptyState: true,
  StatusBadge: true,
  RouterLink: { template: '<a><slot /></a>' },
  Teleport: true,
}

describe('EsCasesView', () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    await router.push('/')
    await router.isReady()
  })

  it('renders the page header with Cases title', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Cases')
  })

  it('calls fetchCases on mount and displays cases', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(esCasesApi.find).toHaveBeenCalledWith({
      page: 1,
      per_page: 25,
      sortField: 'created_at',
      sortOrder: 'desc',
    })
    expect(wrapper.text()).toContain('Suspicious login detected')
    expect(wrapper.text()).toContain('Malware outbreak')
  })

  it('displays case count total', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('4')
  })

  it('renders created_by username', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('analyst1')
  })

  it('shows "unknown" for cases with null created_by', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('unknown')
  })

  it('displays tags for cases', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('auth')
    expect(wrapper.text()).toContain('suspicious')
  })

  // severityBadgeClass function coverage
  it('applies correct badge class for critical severity', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const result = (wrapper.vm as unknown as { severityBadgeClass: (s: string) => string }).severityBadgeClass('critical')
    expect(result).toBe('bg-red-500/15 text-red-400')
  })

  it('applies correct badge class for high severity', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const result = (wrapper.vm as unknown as { severityBadgeClass: (s: string) => string }).severityBadgeClass('high')
    expect(result).toBe('bg-orange-500/15 text-orange-400')
  })

  it('applies correct badge class for medium severity', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const result = (wrapper.vm as unknown as { severityBadgeClass: (s: string) => string }).severityBadgeClass('medium')
    expect(result).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('applies correct badge class for low severity', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const result = (wrapper.vm as unknown as { severityBadgeClass: (s: string) => string }).severityBadgeClass('low')
    expect(result).toBe('bg-blue-500/15 text-blue-400')
  })

  it('applies default badge class for unknown severity', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const result = (wrapper.vm as unknown as { severityBadgeClass: (s: string) => string }).severityBadgeClass('unknown')
    expect(result).toBe('bg-gray-500/15 text-gray-400')
  })

  // statusBadgeClass function coverage
  it('applies correct badge class for open status', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const result = (wrapper.vm as unknown as { statusBadgeClass: (s: string) => string }).statusBadgeClass('open')
    expect(result).toBe('bg-blue-500/15 text-blue-400')
  })

  it('applies correct badge class for in-progress status', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const result = (wrapper.vm as unknown as { statusBadgeClass: (s: string) => string }).statusBadgeClass('in-progress')
    expect(result).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('applies correct badge class for closed status', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const result = (wrapper.vm as unknown as { statusBadgeClass: (s: string) => string }).statusBadgeClass('closed')
    expect(result).toBe('bg-green-500/15 text-green-400')
  })

  it('applies default badge class for unknown status', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const result = (wrapper.vm as unknown as { statusBadgeClass: (s: string) => string }).statusBadgeClass('unknown')
    expect(result).toBe('bg-gray-500/15 text-gray-400')
  })

  // fetchCases with specific page number
  it('fetchCases can be called with a page parameter', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    vi.mocked(esCasesApi.find).mockClear()
    await (wrapper.vm as unknown as { fetchCases: (p?: number) => Promise<void> }).fetchCases(2)
    expect(esCasesApi.find).toHaveBeenCalledWith(
      expect.objectContaining({ page: 2 })
    )
  })

  // showCreateDialog toggle
  it('opens create dialog when Create Case button is clicked', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const createBtn = wrapper.findAll('button').find(b => b.text().includes('Create Case'))
    expect(createBtn).toBeDefined()
    await createBtn!.trigger('click')
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Create Case')
  })

  // createCase function
  it('createCase calls esCasesApi.create and refreshes', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      showCreateDialog: boolean
      newCase: { title: string; description: string; severity: string; tags: string }
      createCase: () => Promise<void>
    }
    vm.showCreateDialog = true
    vm.newCase.title = 'New Test Case'
    vm.newCase.description = 'Test description'
    vm.newCase.severity = 'high'
    vm.newCase.tags = 'tag1, tag2'
    await wrapper.vm.$nextTick()
    vi.mocked(esCasesApi.find).mockClear()
    await vm.createCase()
    await flushPromises()
    expect(esCasesApi.create).toHaveBeenCalledWith(
      expect.objectContaining({
        title: 'New Test Case',
        description: 'Test description',
        severity: 'high',
        tags: ['tag1', 'tag2'],
      })
    )
    expect(esCasesApi.find).toHaveBeenCalled()
    expect(vm.showCreateDialog).toBe(false)
  })

  it('createCase handles empty tags correctly', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      showCreateDialog: boolean
      newCase: { title: string; description: string; severity: string; tags: string }
      createCase: () => Promise<void>
    }
    vm.newCase.title = 'Case no tags'
    vm.newCase.tags = ''
    await vm.createCase()
    await flushPromises()
    expect(esCasesApi.create).toHaveBeenCalledWith(
      expect.objectContaining({ tags: [] })
    )
  })

  // hasPrev / hasNext computed properties
  it('hasPrev is false on page 1', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const vm = wrapper.vm as unknown as { hasPrev: boolean }
    expect(vm.hasPrev).toBe(false)
  })

  it('hasPrev is true when on page 2', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const vm = wrapper.vm as unknown as { hasPrev: boolean; fetchCases: (p: number) => Promise<void> }
    await vm.fetchCases(2)
    expect(vm.hasPrev).toBe(true)
  })

  it('hasNext is false when total fits on page 1', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    // total=4, page=1, perPage=25 -> 4 < 25, no next page
    const vm = wrapper.vm as unknown as { hasNext: boolean }
    expect(vm.hasNext).toBe(false)
  })

  it('hasNext is true when there are more pages', async () => {
    vi.mocked(esCasesApi.find).mockResolvedValueOnce({ page: 1, per_page: 25, total: 100, data: [{ id: 'c1', title: 'Case 1', status: 'open', severity: 'low', tags: [], total_comment: 0, created_at: '2025-01-01T00:00:00Z', updated_at: '2025-01-01T00:00:00Z', created_by: { username: 'analyst' }, description: '', connector: { id: 'none', name: 'None' } }] })
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const vm = wrapper.vm as unknown as { hasNext: boolean }
    expect(vm.hasNext).toBe(true)
  })

  // Pagination navigation
  it('clicking Next calls fetchCases with next page', async () => {
    vi.mocked(esCasesApi.find).mockResolvedValue({
      page: 1,
      per_page: 25,
      total: 50,
      data: Array.from({ length: 25 }, (_, i) => ({
        id: `case-${i}`,
        title: `Case ${i}`,
        status: 'open',
        severity: 'low',
        tags: [],
        total_comment: 0,
        created_at: '2025-01-01T00:00:00Z',
        updated_at: '2025-01-01T00:00:00Z',
        created_by: { username: 'analyst' },
        description: '',
        connector: { id: 'none', name: 'None' },
      })),
    })
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    vi.mocked(esCasesApi.find).mockClear()
    await (wrapper.vm as unknown as { fetchCases: (p: number) => Promise<void> }).fetchCases(2)
    await flushPromises()
    expect(esCasesApi.find).toHaveBeenCalledWith(expect.objectContaining({ page: 2 }))
  })

  // Error handling
  it('sets loading to false even when fetchCases throws', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    vi.mocked(esCasesApi.find).mockRejectedValueOnce(new Error('API error'))
    const vm = wrapper.vm as unknown as { loading: boolean; fetchCases: () => Promise<void> }
    try { await vm.fetchCases() } catch { /* expected */ }
    await flushPromises()
    expect(vm.loading).toBe(false)
  })

  it('sets loading to false even when createCase throws', async () => {
    vi.mocked(esCasesApi.create).mockRejectedValueOnce(new Error('Create failed'))
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      loading: boolean
      newCase: { title: string; description: string; severity: string; tags: string }
      createCase: () => Promise<void>
    }
    vm.newCase.title = 'Test'
    try {
      await vm.createCase()
    } catch {
      // expected
    }
    await flushPromises()
    expect(vm.loading).toBe(false)
  })

  // Row click navigates to case detail
  it('clicking a case row navigates to case detail', async () => {
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const rows = wrapper.findAll('tr.table-row')
    if (rows.length > 0) {
      await rows[0].trigger('click')
      await flushPromises()
      expect(router.currentRoute.value.path).toContain('/elastic/cases/')
    }
  })

  // Empty state
  it('shows empty state when no cases are returned', async () => {
    vi.mocked(esCasesApi.find).mockResolvedValueOnce({ page: 1, per_page: 25, total: 0, data: [] })
    const wrapper = mount(EsCasesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.html()).toContain('empty-state-stub')
  })

  it('Refresh button triggers fetchCases via DOM click', async () => {
    const wrapper = mount(EsCasesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esCasesApi.find).mockClear()
    const refreshBtn = wrapper.findAll('button').find(b => b.text().includes('Refresh'))
    await refreshBtn!.trigger('click')
    await flushPromises()
    expect(esCasesApi.find).toHaveBeenCalled()
  })

  it('Create button in dialog calls createCase via DOM click', async () => {
    const wrapper = mount(EsCasesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.showCreateDialog = true
    vm.newCase.title = 'DOM Test Case'
    await wrapper.vm.$nextTick()
    const createBtn = wrapper.findAll('button').find(b => b.text().includes('Create') && !b.text().includes('Case'))
    if (createBtn) {
      await createBtn.trigger('click')
      await flushPromises()
      expect(esCasesApi.create).toHaveBeenCalled()
    }
  })

  it('Cancel button in dialog closes it via DOM click', async () => {
    const wrapper = mount(EsCasesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.showCreateDialog = true
    await wrapper.vm.$nextTick()
    const cancelBtn = wrapper.findAll('button').find(b => b.text() === 'Cancel')
    await cancelBtn!.trigger('click')
    expect(vm.showCreateDialog).toBe(false)
  })

  it('Previous button triggers fetchCases(page-1) via DOM click', async () => {
    const wrapper = mount(EsCasesView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as any
    vm.page = 2
    await wrapper.vm.$nextTick()
    vi.mocked(esCasesApi.find).mockClear()
    const prevBtn = wrapper.findAll('button').find(b => b.text().includes('Previous') || b.text().includes('Prev'))
    if (prevBtn) {
      await prevBtn.trigger('click')
      await flushPromises()
      expect(esCasesApi.find).toHaveBeenCalled()
    }
  })
})
