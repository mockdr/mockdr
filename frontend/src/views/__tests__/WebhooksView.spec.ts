import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'

vi.mock('../../api/system', () => ({
  webhooksApi: {
    list: vi.fn().mockResolvedValue({
      data: [
        {
          id: 'hook-1',
          url: 'https://example.com/webhook',
          description: 'Primary webhook',
          secret: 'secret-abc',
          event_types: ['threat.created', 'alert.created'],
          active: true,
          created_at: '2025-03-01T12:00:00Z',
          updated_at: '2025-03-01T12:00:00Z',
        },
        {
          id: 'hook-2',
          url: 'https://backup.example.com/hook',
          description: '',
          secret: '',
          event_types: ['agent.offline'],
          active: false,
          created_at: '2025-04-10T08:00:00Z',
          updated_at: '2025-04-10T08:00:00Z',
        },
      ],
    }),
    create: vi.fn().mockResolvedValue({
      data: {
        id: 'hook-new',
        url: 'https://new.example.com/hook',
        description: 'New webhook',
        secret: '',
        event_types: ['threat.created'],
        active: true,
        created_at: '2025-05-01T00:00:00Z',
        updated_at: '2025-05-01T00:00:00Z',
      },
    }),
    delete: vi.fn().mockResolvedValue({ data: null }),
    fire: vi.fn().mockResolvedValue({ data: null }),
  },
}))

import { webhooksApi } from '@/api/system'
import WebhooksView from '@/views/WebhooksView.vue'

const GLOBAL_STUBS = {
  LoadingSkeleton: true,
  EmptyState: true,
  StatusBadge: true,
  RouterLink: { template: '<a><slot /></a>' },
  Teleport: true,
}

describe('WebhooksView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(webhooksApi.list).mockResolvedValue({
      data: [
        {
          id: 'hook-1',
          url: 'https://example.com/webhook',
          description: 'Primary webhook',
          secret: 'secret-abc',
          event_types: ['threat.created', 'alert.created'],
          active: true,
          created_at: '2025-03-01T12:00:00Z',
          updated_at: '2025-03-01T12:00:00Z',
        },
        {
          id: 'hook-2',
          url: 'https://backup.example.com/hook',
          description: '',
          secret: '',
          event_types: ['agent.offline'],
          active: false,
          created_at: '2025-04-10T08:00:00Z',
          updated_at: '2025-04-10T08:00:00Z',
        },
      ],
    })
    vi.mocked(webhooksApi.create).mockResolvedValue({
      data: {
        id: 'hook-new',
        url: 'https://new.example.com/hook',
        description: 'New webhook',
        secret: '',
        event_types: ['threat.created'],
        active: true,
        created_at: '2025-05-01T00:00:00Z',
        updated_at: '2025-05-01T00:00:00Z',
      },
    })
    vi.mocked(webhooksApi.delete).mockResolvedValue({ data: null })
    vi.mocked(webhooksApi.fire).mockResolvedValue({ data: null })
  })

  // ── Basic rendering ───────────────────────────────────────────────────────

  it('renders without error', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the Webhook Subscriptions heading', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('Webhook Subscriptions')
  })

  it('calls webhooksApi.list on mount', async () => {
    mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(webhooksApi.list).toHaveBeenCalledOnce()
  })

  it('renders webhook URLs after load', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('https://example.com/webhook')
    expect(w.text()).toContain('https://backup.example.com/hook')
  })

  it('renders webhook count in subtitle', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('2 registered endpoints')
  })

  it('renders event type badges', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('threat.created')
    expect(w.text()).toContain('agent.offline')
  })

  it('renders Add Webhook button', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('Add Webhook')
  })

  it('renders Fire Test Event section with all event type buttons', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('Fire Test Event')
    expect(w.text()).toContain('agent.offline')
    expect(w.text()).toContain('agent.infected')
    expect(w.text()).toContain('alert.created')
  })

  // ── fetchHooks ────────────────────────────────────────────────────────────

  it('fetchHooks re-calls webhooksApi.list', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    vi.mocked(webhooksApi.list).mockClear()
    await (w.vm as any).fetchHooks()
    await flushPromises()
    expect(webhooksApi.list).toHaveBeenCalledOnce()
  })

  it('fetchHooks refreshes the hooks list with new data', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    vi.mocked(webhooksApi.list).mockResolvedValueOnce({
      data: [
        {
          id: 'hook-refreshed',
          url: 'https://refreshed.example.com/hook',
          description: 'Refreshed',
          secret: '',
          event_types: ['threat.updated'],
          active: true,
          created_at: '2025-06-01T00:00:00Z',
          updated_at: '2025-06-01T00:00:00Z',
        },
      ],
    })
    await (w.vm as any).fetchHooks()
    await flushPromises()
    expect(w.text()).toContain('https://refreshed.example.com/hook')
  })

  it('Refresh button triggers fetchHooks', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    vi.mocked(webhooksApi.list).mockClear()
    const refreshButton = w.findAll('button').find(b => b.text().includes('Refresh'))
    expect(refreshButton).toBeDefined()
    await refreshButton!.trigger('click')
    await flushPromises()
    expect(webhooksApi.list).toHaveBeenCalledOnce()
  })

  // ── deleteHook ────────────────────────────────────────────────────────────

  it('deleteHook calls webhooksApi.delete with the correct id', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    await (w.vm as any).deleteHook('hook-1')
    await flushPromises()
    expect(webhooksApi.delete).toHaveBeenCalledWith('hook-1')
  })

  it('deleteHook removes the hook from the list', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('https://example.com/webhook')
    await (w.vm as any).deleteHook('hook-1')
    await flushPromises()
    expect(w.text()).not.toContain('https://example.com/webhook')
  })

  it('deleteHook sets error message on API failure (Error instance)', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    vi.mocked(webhooksApi.delete).mockRejectedValueOnce(new Error('Delete failed'))
    await (w.vm as any).deleteHook('hook-1')
    await flushPromises()
    expect((w.vm as any).error).toBe('Delete failed')
  })

  it('deleteHook sets generic error message when non-Error is thrown', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    vi.mocked(webhooksApi.delete).mockRejectedValueOnce('some string error')
    await (w.vm as any).deleteHook('hook-1')
    await flushPromises()
    expect((w.vm as any).error).toBe('Failed to delete webhook')
  })

  it('renders error banner when error is set after failed delete', async () => {
    vi.mocked(webhooksApi.delete).mockRejectedValueOnce(new Error('Delete failed'))
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    await (w.vm as any).deleteHook('hook-1')
    await flushPromises()
    expect(w.text()).toContain('Delete failed')
  })

  // ── fireEvent ─────────────────────────────────────────────────────────────

  it('fireEvent calls webhooksApi.fire with the event type', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    await (w.vm as any).fireEvent('threat.created')
    await flushPromises()
    expect(webhooksApi.fire).toHaveBeenCalledWith('threat.created')
  })

  it('fireEvent resets firing to null after successful call', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    await (w.vm as any).fireEvent('alert.created')
    await flushPromises()
    expect((w.vm as any).firing).toBeNull()
  })

  it('fireEvent resets firing to null even when fire throws', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    vi.mocked(webhooksApi.fire).mockRejectedValueOnce(new Error('fire error'))
    await (w.vm as any).fireEvent('agent.offline').catch(() => {})
    await flushPromises()
    expect((w.vm as any).firing).toBeNull()
  })

  it('clicking a fire event button invokes fireEvent', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const fireButton = w.findAll('button').find(b => b.text().trim() === 'threat.created')
    expect(fireButton).toBeDefined()
    await fireButton!.trigger('click')
    await flushPromises()
    expect(webhooksApi.fire).toHaveBeenCalledWith('threat.created')
  })

  // ── toggleEventType ───────────────────────────────────────────────────────

  it('toggleEventType adds an event type when not present', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect((w.vm as any).form.event_types).not.toContain('threat.created')
    ;(w.vm as any).toggleEventType('threat.created')
    expect((w.vm as any).form.event_types).toContain('threat.created')
  })

  it('toggleEventType removes an event type when already present', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).toggleEventType('threat.created')
    expect((w.vm as any).form.event_types).toContain('threat.created')
    ;(w.vm as any).toggleEventType('threat.created')
    expect((w.vm as any).form.event_types).not.toContain('threat.created')
  })

  it('toggleEventType can add multiple event types independently', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).toggleEventType('threat.created')
    ;(w.vm as any).toggleEventType('alert.created')
    ;(w.vm as any).toggleEventType('agent.offline')
    expect((w.vm as any).form.event_types).toContain('threat.created')
    expect((w.vm as any).form.event_types).toContain('alert.created')
    expect((w.vm as any).form.event_types).toContain('agent.offline')
  })

  // ── createHook ────────────────────────────────────────────────────────────

  it('createHook sets createError when URL is missing', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).form.url = ''
    await (w.vm as any).createHook()
    expect((w.vm as any).createError).toBe('URL is required')
  })

  it('createHook sets createError when no event types are selected', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).form.url = 'https://example.com/hook'
    ;(w.vm as any).form.event_types = []
    await (w.vm as any).createHook()
    expect((w.vm as any).createError).toBe('Select at least one event type')
  })

  it('createHook calls webhooksApi.create with correct payload', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).form.url = 'https://new.example.com/hook'
    ;(w.vm as any).form.description = 'New webhook'
    ;(w.vm as any).form.secret = ''
    ;(w.vm as any).form.event_types = ['threat.created']
    await (w.vm as any).createHook()
    await flushPromises()
    expect(webhooksApi.create).toHaveBeenCalledWith({
      url: 'https://new.example.com/hook',
      description: 'New webhook',
      secret: '',
      event_types: ['threat.created'],
    })
  })

  it('createHook adds new hook to the list on success', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).form.url = 'https://new.example.com/hook'
    ;(w.vm as any).form.event_types = ['threat.created']
    await (w.vm as any).createHook()
    await flushPromises()
    expect(w.text()).toContain('https://new.example.com/hook')
  })

  it('createHook resets form and closes modal on success', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).showCreate = true
    ;(w.vm as any).form.url = 'https://new.example.com/hook'
    ;(w.vm as any).form.event_types = ['threat.created']
    await (w.vm as any).createHook()
    await flushPromises()
    expect((w.vm as any).showCreate).toBe(false)
    expect((w.vm as any).form.url).toBe('')
    expect((w.vm as any).form.event_types).toHaveLength(0)
  })

  it('createHook sets createError on API failure (Error instance)', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    vi.mocked(webhooksApi.create).mockRejectedValueOnce(new Error('Server error'))
    ;(w.vm as any).form.url = 'https://new.example.com/hook'
    ;(w.vm as any).form.event_types = ['threat.created']
    await (w.vm as any).createHook()
    await flushPromises()
    expect((w.vm as any).createError).toBe('Server error')
  })

  it('createHook sets generic createError when non-Error is thrown', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    vi.mocked(webhooksApi.create).mockRejectedValueOnce('unknown')
    ;(w.vm as any).form.url = 'https://new.example.com/hook'
    ;(w.vm as any).form.event_types = ['threat.created']
    await (w.vm as any).createHook()
    await flushPromises()
    expect((w.vm as any).createError).toBe('Failed to create webhook')
  })

  // ── showCreate modal toggle ───────────────────────────────────────────────

  it('clicking Add Webhook opens the create modal', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect((w.vm as any).showCreate).toBe(false)
    const addBtn = w.findAll('button').find(b => b.text().includes('Add Webhook'))
    expect(addBtn).toBeDefined()
    await addBtn!.trigger('click')
    expect((w.vm as any).showCreate).toBe(true)
  })

  // ── singular vs plural endpoint label ────────────────────────────────────

  it('shows "1 registered endpoint" (singular) for a single webhook', async () => {
    vi.mocked(webhooksApi.list).mockResolvedValueOnce({
      data: [
        {
          id: 'hook-only',
          url: 'https://only.example.com/hook',
          description: '',
          secret: '',
          event_types: ['threat.created'],
          active: true,
          created_at: '2025-01-01T00:00:00Z',
          updated_at: '2025-01-01T00:00:00Z',
        },
      ],
    })
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('1 registered endpoint')
    expect(w.text()).not.toContain('1 registered endpoints')
  })

  it('delete button calls deleteHook via DOM click', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const deleteBtn = w.find('button.flex-shrink-0')
    await deleteBtn.trigger('click')
    await flushPromises()
    expect(webhooksApi.delete).toHaveBeenCalled()
  })

  it('X button in dialog closes modal via DOM click', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).showCreate = true
    await w.vm.$nextTick()
    const xBtn = w.find('button.text-s1-muted.hover\\:text-s1-text')
    await xBtn.trigger('click')
    expect((w.vm as any).showCreate).toBe(false)
  })

  it('Cancel button in dialog closes modal via DOM click', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).showCreate = true
    await w.vm.$nextTick()
    const cancelBtn = w.findAll('button').find(b => b.text() === 'Cancel')
    await cancelBtn!.trigger('click')
    expect((w.vm as any).showCreate).toBe(false)
  })

  it('Create button in dialog calls createHook via DOM click', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).showCreate = true
    ;(w.vm as any).form.url = 'https://dom-test.example.com/hook'
    ;(w.vm as any).form.event_types = ['threat.created']
    await w.vm.$nextTick()
    const createBtn = w.findAll('button').find(b => b.text() === 'Create')
    await createBtn!.trigger('click')
    await flushPromises()
    expect(webhooksApi.create).toHaveBeenCalled()
  })

  it('event type toggle button in dialog calls toggleEventType via DOM click', async () => {
    const w = mount(WebhooksView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).showCreate = true
    await w.vm.$nextTick()
    const eventTypeBtn = w.findAll('button').find(b => b.text().includes('threat.created') && b.classes().some(c => c.includes('rounded-full')))
    if (eventTypeBtn) {
      await eventTypeBtn.trigger('click')
      expect((w.vm as any).form.event_types).toContain('threat.created')
    }
  })
})
