import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

const MOCK_CASE = {
  id: 'test-case-id',
  title: 'Test Security Case',
  description: 'Investigating suspicious activity',
  status: 'open',
  severity: 'high',
  tags: ['malware', 'endpoint'],
  created_at: '2025-01-01T00:00:00Z',
  updated_at: '2025-01-01T12:00:00Z',
  total_comment: 2,
  created_by: { username: 'analyst1' },
  connector: { id: 'none', name: 'None' },
}

const MOCK_COMMENTS = [
  {
    id: 'comment-1',
    comment: 'Initial investigation started',
    type: 'user',
    created_at: '2025-01-01T01:00:00Z',
    created_by: { username: 'analyst1' },
  },
  {
    id: 'comment-2',
    comment: 'Found suspicious process execution',
    type: 'user',
    created_at: '2025-01-01T02:00:00Z',
    created_by: { username: 'analyst2' },
  },
]

vi.mock('../../../api/elastic', () => ({
  esCasesApi: {
    get: vi.fn().mockResolvedValue({
      id: 'test-case-id',
      title: 'Test Security Case',
      description: 'Investigating suspicious activity',
      status: 'open',
      severity: 'high',
      tags: ['malware', 'endpoint'],
      created_at: '2025-01-01T00:00:00Z',
      updated_at: '2025-01-01T12:00:00Z',
      total_comment: 2,
      created_by: { username: 'analyst1' },
      connector: { id: 'none', name: 'None' },
    }),
    getComments: vi.fn().mockResolvedValue({
      page: 1,
      per_page: 20,
      total: 2,
      data: [
        {
          id: 'comment-1',
          comment: 'Initial investigation started',
          created_at: '2025-01-01T01:00:00Z',
          created_by: { username: 'analyst1' },
        },
        {
          id: 'comment-2',
          comment: 'Found suspicious process execution',
          created_at: '2025-01-01T02:00:00Z',
          created_by: { username: 'analyst2' },
        },
      ],
    }),
    addComment: vi.fn().mockResolvedValue({ id: 'comment-new' }),
    update: vi.fn().mockResolvedValue([]),
  },
}))

import EsCaseDetailView from '@/views/elastic/EsCaseDetailView.vue'
import { esCasesApi } from '@/api/elastic'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/elastic/cases', component: { template: '<div />' } },
    { path: '/elastic/cases/:id', component: EsCaseDetailView },
  ],
})

const STUBS = {
  LoadingSkeleton: true,
  RouterLink: { template: '<a><slot /></a>' },
  Teleport: true,
}

describe('EsCaseDetailView', () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    vi.mocked(esCasesApi.get).mockResolvedValue(MOCK_CASE)
    vi.mocked(esCasesApi.getComments).mockResolvedValue({ page: 1, per_page: 20, total: 2, data: MOCK_COMMENTS })
    await router.push('/elastic/cases/test-case-id')
    await router.isReady()
  })

  it('renders case title after loading', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('Test Security Case')
  })

  it('calls esCasesApi.get and getComments on mount', async () => {
    mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(esCasesApi.get).toHaveBeenCalledWith('test-case-id')
    expect(esCasesApi.getComments).toHaveBeenCalledWith('test-case-id')
  })

  it('displays case description', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('Investigating suspicious activity')
  })

  it('displays comment content', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('Initial investigation started')
    expect(wrapper.text()).toContain('Found suspicious process execution')
  })

  it('displays comment author names', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('analyst1')
    expect(wrapper.text()).toContain('analyst2')
  })

  it('displays tags when present', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('malware')
    expect(wrapper.text()).toContain('endpoint')
  })

  it('sets loading to false after mount completes', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  // severityBadgeClass — all branches
  it('severityBadgeClass returns red for critical', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('critical')).toBe('bg-red-500/15 text-red-400')
  })

  it('severityBadgeClass returns orange for high', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('high')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('severityBadgeClass returns yellow for medium', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('medium')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('severityBadgeClass returns blue for low', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('low')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('severityBadgeClass returns gray for unknown', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('unknown')).toBe('bg-gray-500/15 text-gray-400')
  })

  // statusBadgeClass — all branches
  it('statusBadgeClass returns blue for open', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('open')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('statusBadgeClass returns yellow for in-progress', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('in-progress')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('statusBadgeClass returns green for closed', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('closed')).toBe('bg-green-500/15 text-green-400')
  })

  it('statusBadgeClass returns gray for unknown status', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('pending')).toBe('bg-gray-500/15 text-gray-400')
  })

  // formatTime
  it('formatTime returns formatted date string for valid timestamp', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const result = (wrapper.vm as any).formatTime('2025-06-15T10:30:00Z')
    expect(typeof result).toBe('string')
    expect(result).not.toBe('--')
    expect(result.length).toBeGreaterThan(0)
  })

  it('formatTime returns "--" for empty string', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).formatTime('')).toBe('--')
  })

  // addComment — empty guard
  it('addComment does nothing when commentText is empty', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).commentText = ''
    vi.mocked(esCasesApi.addComment).mockClear()
    await (wrapper.vm as any).addComment()
    await flushPromises()
    expect(esCasesApi.addComment).not.toHaveBeenCalled()
  })

  it('addComment does nothing when commentText is only whitespace', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).commentText = '   '
    vi.mocked(esCasesApi.addComment).mockClear()
    await (wrapper.vm as any).addComment()
    await flushPromises()
    expect(esCasesApi.addComment).not.toHaveBeenCalled()
  })

  // addComment — success path
  it('addComment calls esCasesApi.addComment with correct args', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).commentText = 'New comment text'
    await (wrapper.vm as any).addComment()
    await flushPromises()
    expect(esCasesApi.addComment).toHaveBeenCalledWith('test-case-id', {
      comment: 'New comment text',
      type: 'user',
    })
  })

  it('addComment clears commentText after success', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).commentText = 'My comment'
    await (wrapper.vm as any).addComment()
    await flushPromises()
    expect((wrapper.vm as any).commentText).toBe('')
  })

  it('addComment refreshes comments after posting', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esCasesApi.getComments).mockClear()
    ;(wrapper.vm as any).commentText = 'Refreshed comment'
    await (wrapper.vm as any).addComment()
    await flushPromises()
    expect(esCasesApi.getComments).toHaveBeenCalledWith('test-case-id')
  })

  it('addComment sets submitting to false after completion', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).commentText = 'Test comment'
    await (wrapper.vm as any).addComment()
    await flushPromises()
    expect((wrapper.vm as any).submitting).toBe(false)
  })

  it('addComment sets submitting to false on error', async () => {
    vi.mocked(esCasesApi.addComment).mockRejectedValueOnce(new Error('add failed'))
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).commentText = 'Test comment'
    try { await (wrapper.vm as any).addComment() } catch { /* expected */ }
    await flushPromises()
    expect((wrapper.vm as any).submitting).toBe(false)
  })

  // updateStatus — guard when caseData is null
  it('updateStatus does nothing when caseData is null', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).caseData = null
    vi.mocked(esCasesApi.update).mockClear()
    await (wrapper.vm as any).updateStatus('closed')
    await flushPromises()
    expect(esCasesApi.update).not.toHaveBeenCalled()
  })

  // updateStatus — success path
  it('updateStatus calls esCasesApi.update with correct payload', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    await (wrapper.vm as any).updateStatus('in-progress')
    await flushPromises()
    expect(esCasesApi.update).toHaveBeenCalledWith({
      cases: [
        expect.objectContaining({
          id: 'test-case-id',
          status: 'in-progress',
        }),
      ],
    })
  })

  it('updateStatus updates caseData.status locally on success', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    await (wrapper.vm as any).updateStatus('closed')
    await flushPromises()
    expect((wrapper.vm as any).caseData.status).toBe('closed')
  })

  it('updateStatus clears error on success', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).error = 'previous error'
    await (wrapper.vm as any).updateStatus('closed')
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('')
  })

  it('updateStatus can reopen a closed case', async () => {
    vi.mocked(esCasesApi.get).mockResolvedValue({ ...MOCK_CASE, status: 'closed' })
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    await (wrapper.vm as any).updateStatus('open')
    await flushPromises()
    expect(esCasesApi.update).toHaveBeenCalledWith(
      expect.objectContaining({
        cases: [expect.objectContaining({ status: 'open' })],
      })
    )
  })

  it('updateStatus sets error message when API call fails', async () => {
    vi.mocked(esCasesApi.update).mockRejectedValueOnce(new Error('Update failed'))
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    await (wrapper.vm as any).updateStatus('closed')
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('Update failed')
  })

  it('shows "Case not found" when caseData is null after loading', async () => {
    vi.mocked(esCasesApi.get).mockResolvedValueOnce(null as unknown as import('../../../types/elastic').EsCase)
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('Case not found')
  })

  it('shows "No comments yet" when comment list is empty', async () => {
    vi.mocked(esCasesApi.getComments).mockResolvedValueOnce({ page: 1, per_page: 20, total: 0, data: [] })
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('No comments yet')
  })

  it('Mark In Progress button calls updateStatus via DOM click', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esCasesApi.update).mockClear()
    const btn = wrapper.findAll('button').find(b => b.text().includes('In Progress'))
    await btn!.trigger('click')
    await flushPromises()
    expect(esCasesApi.update).toHaveBeenCalledWith(
      expect.objectContaining({ cases: [expect.objectContaining({ status: 'in-progress' })] })
    )
  })

  it('Close button calls updateStatus closed via DOM click', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esCasesApi.update).mockClear()
    const btn = wrapper.findAll('button').find(b => b.text() === 'Close')
    await btn!.trigger('click')
    await flushPromises()
    expect(esCasesApi.update).toHaveBeenCalledWith(
      expect.objectContaining({ cases: [expect.objectContaining({ status: 'closed' })] })
    )
  })

  it('Send button calls addComment via DOM click', async () => {
    const wrapper = mount(EsCaseDetailView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).commentText = 'dom comment'
    await wrapper.vm.$nextTick()
    vi.mocked(esCasesApi.addComment).mockClear()
    // Find the send button (has no text, just icon) near the textarea
    const allBtns = wrapper.findAll('button')
    const lastBtn = allBtns[allBtns.length - 1]
    if (lastBtn) {
      await lastBtn.trigger('click')
      await flushPromises()
      expect(esCasesApi.addComment).toHaveBeenCalled()
    }
  })
})
