import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'

vi.mock('../../api/misc', () => ({
  dvApi: {
    initQuery: vi.fn().mockResolvedValue({ data: { queryId: 'q-123' } }),
    queryStatus: vi.fn().mockResolvedValue({ data: { responseState: 'FINISHED', progressPercentage: 100 } }),
    events: vi.fn().mockResolvedValue({ data: [{ id: 'ev1', type: 'Process', srcProcName: 'chrome.exe', srcIp: '10.0.0.1', dstIp: '1.1.1.1', createdAt: '2025-01-01T00:00:00Z' }], pagination: { totalItems: 1 } }),
    cancel: vi.fn().mockResolvedValue({}),
  },
}))

import DeepVisibilityView from '@/views/DeepVisibilityView.vue'

const stubs = { LoadingSkeleton: true, EmptyState: true }

describe('DeepVisibilityView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('renders Deep Visibility heading', () => {
    const w = mount(DeepVisibilityView, { global: { stubs } })
    expect(w.text()).toContain('Deep Visibility')
  })

  it('runQuery does nothing when queryText is empty', async () => {
    const { dvApi } = await import('../../api/misc')
    const w = mount(DeepVisibilityView, { global: { stubs } })
    ;(w.vm as any).queryText = ''
    await (w.vm as any).runQuery()
    expect(dvApi.initQuery).not.toHaveBeenCalled()
  })

  it('runQuery calls dvApi.initQuery', async () => {
    const { dvApi } = await import('../../api/misc')
    const w = mount(DeepVisibilityView, { global: { stubs } })
    ;(w.vm as any).queryText = 'EventType = "Process"'
    const runPromise = (w.vm as any).runQuery()
    await flushPromises()
    vi.advanceTimersByTime(600)
    await flushPromises()
    await runPromise
    expect(dvApi.initQuery).toHaveBeenCalled()
  })

  it('cancelQuery calls dvApi.cancel', async () => {
    const { dvApi } = await import('../../api/misc')
    const w = mount(DeepVisibilityView, { global: { stubs } })
    ;(w.vm as any).currentQueryId = 'q-123'
    await (w.vm as any).cancelQuery()
    expect(dvApi.cancel).toHaveBeenCalledWith('q-123')
  })

  it('cancelQuery does nothing when no currentQueryId', async () => {
    const { dvApi } = await import('../../api/misc')
    const w = mount(DeepVisibilityView, { global: { stubs } })
    ;(w.vm as any).currentQueryId = null
    await (w.vm as any).cancelQuery()
    expect(dvApi.cancel).not.toHaveBeenCalled()
  })

  it('loadEvents calls dvApi.events', async () => {
    const { dvApi } = await import('../../api/misc')
    const w = mount(DeepVisibilityView, { global: { stubs } })
    ;(w.vm as any).currentQueryId = 'q-123'
    await (w.vm as any).loadEvents(true)
    expect(dvApi.events).toHaveBeenCalled()
  })

  it('loadEvents appends events when reset is false', async () => {
    const w = mount(DeepVisibilityView, { global: { stubs } })
    ;(w.vm as any).currentQueryId = 'q-123'
    ;(w.vm as any).events = [{ id: 'ev0', type: 'File' }]
    await (w.vm as any).loadEvents(false)
    expect((w.vm as any).events.length).toBeGreaterThan(1)
  })

  it('EVENT_TYPE_COLOR has entries for Process and Network', () => {
    const w = mount(DeepVisibilityView, { global: { stubs } })
    expect((w.vm as any).EVENT_TYPE_COLOR['Process']).toBeTruthy()
    expect((w.vm as any).EVENT_TYPE_COLOR['Network']).toBeTruthy()
  })

  // DOM trigger tests – exercise the template-compiled event handler arrow functions

  it('Run Query button triggers runQuery via DOM click', async () => {
    const { dvApi } = await import('../../api/misc')
    const w = mount(DeepVisibilityView, { global: { stubs } })
    await flushPromises()
    // set queryText so runQuery does not early-return
    ;(w.vm as any).queryText = 'EventType = "Process"'
    await w.vm.$nextTick()
    const btn = w.findAll('button').find(b => b.text().includes('Run Query'))
    expect(btn).toBeDefined()
    await btn!.trigger('click')
    await flushPromises()
    vi.advanceTimersByTime(600)
    await flushPromises()
    expect(dvApi.initQuery).toHaveBeenCalled()
  })

  it('Cancel button triggers cancelQuery via DOM click', async () => {
    const { dvApi } = await import('../../api/misc')
    const w = mount(DeepVisibilityView, { global: { stubs } })
    await flushPromises()
    // put the component into running state with a query id so Cancel is visible and cancelQuery can call dvApi.cancel
    ;(w.vm as any).running = true
    ;(w.vm as any).currentQueryId = 'q-cancel'
    await w.vm.$nextTick()
    const btn = w.findAll('button').find(b => b.text().includes('Cancel'))
    expect(btn).toBeDefined()
    await btn!.trigger('click')
    await flushPromises()
    expect(dvApi.cancel).toHaveBeenCalledWith('q-cancel')
    expect((w.vm as any).running).toBe(false)
  })

  it('Load more button triggers loadEvents(false) via DOM click', async () => {
    const { dvApi } = await import('../../api/misc')
    const w = mount(DeepVisibilityView, { global: { stubs } })
    await flushPromises()
    // populate state so the results section with "Load more" renders
    ;(w.vm as any).events = [{ id: 'ev1', eventType: 'Process', eventTime: '2025-01-01T00:00:00Z', agentName: 'host', processName: 'chrome.exe', user: 'admin', details: '' }]
    ;(w.vm as any).nextCursor = 'cursor-abc'
    ;(w.vm as any).currentQueryId = 'q-123'
    await w.vm.$nextTick()
    const btn = w.findAll('button').find(b => b.text().includes('Load more'))
    expect(btn).toBeDefined()
    await btn!.trigger('click')
    await flushPromises()
    expect(dvApi.events).toHaveBeenCalledWith('q-123', expect.objectContaining({ cursor: 'cursor-abc' }))
  })

  it('queryText textarea v-model updates value via DOM input', async () => {
    const w = mount(DeepVisibilityView, { global: { stubs } })
    await flushPromises()
    const textarea = w.find('textarea')
    await textarea.setValue('EventType = "Network"')
    expect((w.vm as any).queryText).toBe('EventType = "Network"')
  })

  it('fromDate input v-model updates value via DOM input', async () => {
    const w = mount(DeepVisibilityView, { global: { stubs } })
    await flushPromises()
    const inputs = w.findAll('input[type="datetime-local"]')
    await inputs[0].setValue('2025-01-01T00:00')
    expect((w.vm as any).fromDate).toBe('2025-01-01T00:00')
  })

  it('toDate input v-model updates value via DOM input', async () => {
    const w = mount(DeepVisibilityView, { global: { stubs } })
    await flushPromises()
    const inputs = w.findAll('input[type="datetime-local"]')
    await inputs[1].setValue('2025-01-02T00:00')
    expect((w.vm as any).toDate).toBe('2025-01-02T00:00')
  })
})
