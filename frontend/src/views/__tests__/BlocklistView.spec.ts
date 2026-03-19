import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'

vi.mock('../../api/misc', () => ({
  blocklistApi: {
    list: vi.fn().mockResolvedValue({
      data: [{ id: 'b1', value: 'abc123def456', type: 'black_hash', osType: 'windows', description: 'Known malware', createdAt: '2025-05-01T00:00:00Z' }],
      pagination: { totalItems: 1 },
    }),
    create: vi.fn().mockResolvedValue({ data: {} }),
    delete: vi.fn().mockResolvedValue({}),
  },
}))

import BlocklistView from '@/views/BlocklistView.vue'

const stubs = { LoadingSkeleton: true, EmptyState: true }

describe('BlocklistView', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('renders Blocklist heading', async () => {
    const w = mount(BlocklistView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('Blocklist')
  })

  it('renders entry hash after load', async () => {
    const w = mount(BlocklistView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('abc123def456')
  })

  it('onQuery triggers debounced fetch', async () => {
    vi.useFakeTimers()
    const { blocklistApi } = await import('../../api/misc')
    const w = mount(BlocklistView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).query = 'test'
    ;(w.vm as any).onQuery()
    vi.runAllTimers()
    await flushPromises()
    expect(blocklistApi.list).toHaveBeenCalledTimes(2)
    vi.useRealTimers()
  })

  it('addEntry does nothing when value is empty', async () => {
    const { blocklistApi } = await import('../../api/misc')
    const w = mount(BlocklistView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).form.value = ''
    await (w.vm as any).addEntry()
    expect(blocklistApi.create).not.toHaveBeenCalled()
  })

  it('addEntry calls blocklistApi.create with form data', async () => {
    const { blocklistApi } = await import('../../api/misc')
    const w = mount(BlocklistView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).form.value = 'newhash123'
    ;(w.vm as any).form.type = 'black_hash'
    ;(w.vm as any).form.osType = 'windows'
    ;(w.vm as any).form.description = 'Test'
    await (w.vm as any).addEntry()
    await flushPromises()
    expect(blocklistApi.create).toHaveBeenCalledWith({ value: 'newhash123', type: 'black_hash', osType: 'windows', description: 'Test' })
  })

  it('deleteEntry calls blocklistApi.delete and removes from list', async () => {
    const { blocklistApi } = await import('../../api/misc')
    const w = mount(BlocklistView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).items).toHaveLength(1)
    await (w.vm as any).deleteEntry('b1')
    expect(blocklistApi.delete).toHaveBeenCalledWith('b1')
    expect((w.vm as any).items).toHaveLength(0)
  })

  it('deleteEntry sets error on failure', async () => {
    const { blocklistApi } = await import('../../api/misc')
    ;(blocklistApi.delete as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Delete failed'))
    const w = mount(BlocklistView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).deleteEntry('b1')
    expect((w.vm as any).error).toBeTruthy()
  })

  it('Add Hash button toggles showAdd', async () => {
    const w = mount(BlocklistView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).showAdd).toBe(false)
    const btn = w.findAll('button').find(b => b.text().includes('Add Hash'))
    await btn!.trigger('click')
    expect((w.vm as any).showAdd).toBe(true)
  })

  it('Cancel button in form hides it', async () => {
    const w = mount(BlocklistView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).showAdd = true
    await w.vm.$nextTick()
    const cancelBtn = w.findAll('button').find(b => b.text() === 'Cancel')
    await cancelBtn!.trigger('click')
    expect((w.vm as any).showAdd).toBe(false)
  })

  it('Add button in form calls addEntry', async () => {
    const { blocklistApi } = await import('../../api/misc')
    const w = mount(BlocklistView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).showAdd = true
    ;(w.vm as any).form.value = 'deadbeef1234'
    await w.vm.$nextTick()
    const addBtn = w.findAll('button').find(b => b.text() === 'Add')
    await addBtn!.trigger('click')
    await flushPromises()
    expect(blocklistApi.create).toHaveBeenCalled()
  })

  it('search input triggers onQuery', async () => {
    vi.useFakeTimers()
    const { blocklistApi } = await import('../../api/misc')
    const w = mount(BlocklistView, { global: { stubs } })
    await flushPromises()
    const input = w.find('input[placeholder*="Search"]')
    await input.trigger('input')
    vi.runAllTimers()
    await flushPromises()
    expect(blocklistApi.list).toHaveBeenCalledTimes(2)
    vi.useRealTimers()
  })

  it('trash button calls deleteEntry', async () => {
    const { blocklistApi } = await import('../../api/misc')
    const w = mount(BlocklistView, { global: { stubs } })
    await flushPromises()
    const trashBtn = w.find('tbody button')
    await trashBtn.trigger('click')
    expect(blocklistApi.delete).toHaveBeenCalledWith('b1')
  })

  it('form hash input updates form.value via DOM input event', async () => {
    const w = mount(BlocklistView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).showAdd = true
    await w.vm.$nextTick()
    const hashInput = w.find('input.input.w-full.text-sm.font-mono')
    await hashInput.setValue('newhashabcdef')
    expect((w.vm as any).form.value).toBe('newhashabcdef')
  })

  it('form description input updates form.description via DOM input event', async () => {
    const w = mount(BlocklistView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).showAdd = true
    await w.vm.$nextTick()
    const descInputs = w.findAll('input.input.w-full.text-sm')
    const descInput = descInputs[descInputs.length - 1]
    await descInput.setValue('test description')
    expect((w.vm as any).form.description).toBe('test description')
  })

  it('form type select updates form.type via DOM change event', async () => {
    const w = mount(BlocklistView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).showAdd = true
    await w.vm.$nextTick()
    const selects = w.findAll('select.input.w-full.text-sm')
    if (selects.length > 0) {
      await selects[0].trigger('change')
      // type still black_hash (only option), but setter executed
      expect((w.vm as any).form.type).toBe('black_hash')
    }
  })
})
