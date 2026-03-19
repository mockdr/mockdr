import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'

vi.mock('../../api/misc', () => ({
  exclusionsApi: {
    list: vi.fn().mockResolvedValue({
      data: [{ id: 'e1', value: 'C:\\Windows\\Temp\\*', type: 'path', osType: 'windows', mode: 'suppress', createdAt: '2025-04-01T00:00:00Z' }],
      pagination: { totalItems: 1 },
    }),
    create: vi.fn().mockResolvedValue({ data: {} }),
    delete: vi.fn().mockResolvedValue({}),
  },
}))

import ExclusionsView from '@/views/ExclusionsView.vue'

const stubs = { LoadingSkeleton: true, EmptyState: true }

describe('ExclusionsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.stubGlobal('confirm', vi.fn().mockReturnValue(true))
  })

  it('renders Exclusions heading', async () => {
    const w = mount(ExclusionsView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('Exclusions')
  })

  it('renders exclusion value after load', async () => {
    const w = mount(ExclusionsView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('C:\\Windows\\Temp\\*')
  })

  it('addExclusion does nothing when newPath is empty', async () => {
    const { exclusionsApi } = await import('../../api/misc')
    const w = mount(ExclusionsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).newPath = ''
    await (w.vm as any).addExclusion()
    expect(exclusionsApi.create).not.toHaveBeenCalled()
  })

  it('addExclusion calls exclusionsApi.create with form data', async () => {
    const { exclusionsApi } = await import('../../api/misc')
    const w = mount(ExclusionsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).newPath = '/opt/test'
    ;(w.vm as any).newType = 'path'
    ;(w.vm as any).newOs = 'linux'
    await (w.vm as any).addExclusion()
    await flushPromises()
    expect(exclusionsApi.create).toHaveBeenCalledWith({ value: '/opt/test', type: 'path', osType: 'linux', mode: 'suppress' })
  })

  it('addExclusion sets error on failure', async () => {
    const { exclusionsApi } = await import('../../api/misc')
    ;(exclusionsApi.create as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('API error'))
    const w = mount(ExclusionsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).newPath = '/test'
    await (w.vm as any).addExclusion()
    await flushPromises()
    expect((w.vm as any).error).toBeTruthy()
  })

  it('removeExclusion calls delete and removes from list', async () => {
    const { exclusionsApi } = await import('../../api/misc')
    const w = mount(ExclusionsView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).removeExclusion('e1')
    expect(exclusionsApi.delete).toHaveBeenCalledWith('e1')
    expect((w.vm as any).items).toHaveLength(0)
  })

  it('removeExclusion does nothing when confirm cancelled', async () => {
    const { exclusionsApi } = await import('../../api/misc')
    vi.stubGlobal('confirm', vi.fn().mockReturnValue(false))
    const w = mount(ExclusionsView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).removeExclusion('e1')
    expect(exclusionsApi.delete).not.toHaveBeenCalled()
  })

  it('removeExclusion sets error on failure', async () => {
    const { exclusionsApi } = await import('../../api/misc')
    ;(exclusionsApi.delete as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Delete error'))
    const w = mount(ExclusionsView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).removeExclusion('e1')
    await flushPromises()
    expect((w.vm as any).error).toBeTruthy()
  })

  it('Add Exclusion button toggles showAdd', async () => {
    const w = mount(ExclusionsView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).showAdd).toBe(false)
    const btn = w.findAll('button').find(b => b.text().includes('Add Exclusion'))
    await btn!.trigger('click')
    expect((w.vm as any).showAdd).toBe(true)
  })

  it('Cancel button hides add form', async () => {
    const w = mount(ExclusionsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).showAdd = true
    await w.vm.$nextTick()
    const cancelBtn = w.findAll('button').find(b => b.text() === 'Cancel')
    await cancelBtn!.trigger('click')
    expect((w.vm as any).showAdd).toBe(false)
  })

  it('Add button in form calls addExclusion', async () => {
    const { exclusionsApi } = await import('../../api/misc')
    const w = mount(ExclusionsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).showAdd = true
    ;(w.vm as any).newPath = '/test/path'
    await w.vm.$nextTick()
    const addBtn = w.findAll('button').find(b => b.text() === 'Add')
    await addBtn!.trigger('click')
    await flushPromises()
    expect(exclusionsApi.create).toHaveBeenCalled()
  })

  it('trash button calls removeExclusion', async () => {
    const { exclusionsApi } = await import('../../api/misc')
    const w = mount(ExclusionsView, { global: { stubs } })
    await flushPromises()
    const trashBtn = w.find('tbody button')
    await trashBtn.trigger('click')
    expect(exclusionsApi.delete).toHaveBeenCalledWith('e1')
  })
})
