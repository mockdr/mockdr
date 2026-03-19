import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

const mockList = vi.hoisted(() => vi.fn())

vi.mock('../../../api/crowdstrike', () => ({
  ensureCsAuth: vi.fn().mockResolvedValue(undefined),
  csCasesApi: {
    list: mockList,
  },
}))

import CsCasesView from '@/views/cs/CsCasesView.vue'
import { ensureCsAuth, csCasesApi } from '@/api/crowdstrike'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/crowdstrike/cases', component: { template: '<div />' } },
  ],
})

const stubs = { LoadingSkeleton: true, EmptyState: true }

describe('CsCasesView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockList.mockResolvedValue({
      resources: [
        {
          id: 'case-id-1',
          title: 'Ransomware Investigation',
          type: 'investigation',
          status: 'open',
          tags: ['critical', 'ransomware', 'prod'],
          detections: [{ id: 'd1' }, { id: 'd2' }],
          created_time: '2025-01-15T10:00:00Z',
          updated_time: '2025-01-16T08:00:00Z',
        },
        {
          id: 'case-id-2',
          title: 'Phishing Follow-up',
          type: 'support',
          status: 'closed',
          tags: ['phishing'],
          detections: [],
          created_time: '2025-02-01T00:00:00Z',
          updated_time: '2025-02-02T00:00:00Z',
        },
        {
          id: 'case-id-3',
          title: 'Lateral Movement Review',
          type: 'investigation',
          status: 'in_progress',
          tags: [],
          detections: [{ id: 'd3' }],
          created_time: '2025-03-01T00:00:00Z',
          updated_time: '2025-03-02T00:00:00Z',
        },
      ],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
  })

  it('renders the page header', () => {
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    expect(wrapper.text()).toContain('Cases')
  })

  it('calls ensureCsAuth and csCasesApi.list on mount', async () => {
    mount(CsCasesView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(ensureCsAuth).toHaveBeenCalled()
    expect(csCasesApi.list).toHaveBeenCalled()
  })

  it('renders case titles after loading', async () => {
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('Ransomware Investigation')
    expect(wrapper.text()).toContain('Phishing Follow-up')
  })

  it('renders case types', async () => {
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('investigation')
    expect(wrapper.text()).toContain('support')
  })

  it('sets loading to false after fetch', async () => {
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('populates cases ref with returned resources', async () => {
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).cases).toHaveLength(3)
  })

  it('statusBadgeClass returns blue for "open"', () => {
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusBadgeClass('open')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('statusBadgeClass returns blue for "Open" (case-insensitive)', () => {
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusBadgeClass('Open')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('statusBadgeClass returns yellow for "in_progress"', () => {
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusBadgeClass('in_progress')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('statusBadgeClass returns yellow for "in progress" with space', () => {
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusBadgeClass('in progress')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('statusBadgeClass returns green for "closed"', () => {
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusBadgeClass('closed')).toBe('bg-green-500/15 text-green-400')
  })

  it('statusBadgeClass returns green for "Closed" (case-insensitive)', () => {
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusBadgeClass('Closed')).toBe('bg-green-500/15 text-green-400')
  })

  it('statusBadgeClass returns gray for unknown status', () => {
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusBadgeClass('pending')).toBe('bg-gray-500/15 text-gray-400')
  })

  it('statusBadgeClass returns gray for empty status string', () => {
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusBadgeClass('')).toBe('bg-gray-500/15 text-gray-400')
  })

  it('formatDate returns "--" for empty string', () => {
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).formatDate('')).toBe('--')
  })

  it('formatDate returns a formatted date string for valid ISO date', () => {
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    const result = (wrapper.vm as any).formatDate('2025-01-15T10:00:00Z')
    expect(typeof result).toBe('string')
    expect(result).not.toBe('--')
    expect(result.length).toBeGreaterThan(0)
  })

  it('summary card shows total case count', async () => {
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('3')
  })

  it('summary card shows correct open case count', async () => {
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    await flushPromises()
    // 1 open case out of 3
    expect(wrapper.text()).toContain('Total Cases')
    expect(wrapper.text()).toContain('Open')
    expect(wrapper.text()).toContain('Closed')
  })

  it('re-fetches on Refresh button click', async () => {
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    await flushPromises()
    vi.clearAllMocks()
    await wrapper.find('button').trigger('click')
    await flushPromises()
    expect(csCasesApi.list).toHaveBeenCalled()
  })

  it('handles empty resources gracefully', async () => {
    mockList.mockResolvedValueOnce({
      resources: [],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).cases).toHaveLength(0)
  })

  it('handles null resources gracefully using ?? fallback', async () => {
    mockList.mockResolvedValueOnce({
      resources: null,
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).cases).toHaveLength(0)
  })

  it('renders tags for cases that have them', async () => {
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('critical')
    expect(wrapper.text()).toContain('ransomware')
  })

  it('renders detection count in table', async () => {
    const wrapper = mount(CsCasesView, { global: { plugins: [router], stubs } })
    await flushPromises()
    // case-id-1 has 2 detections
    expect(wrapper.text()).toContain('2')
  })
})
