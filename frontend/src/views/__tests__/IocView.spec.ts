import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import IocView from '@/views/IocView.vue'

const mockIocsList = vi.hoisted(() => vi.fn())
const mockIocsCreate = vi.hoisted(() => vi.fn())
const mockIocsDelete = vi.hoisted(() => vi.fn())

vi.mock('../../api/misc', () => ({
  iocsApi: {
    list: mockIocsList,
    create: mockIocsCreate,
    delete: mockIocsDelete,
  },
}))

const FAKE_IOCS = [
  { uuid: 'ioc1', type: 'IPV4', value: '10.0.0.99', name: 'Suspicious IP', description: 'C2 server', creationTime: '2025-05-10T00:00:00Z' },
  { uuid: 'ioc2', type: 'SHA256', value: 'deadbeef1234567890abcdef', name: 'Bad hash', description: '', creationTime: '2025-05-11T00:00:00Z' },
]

const stubs = { LoadingSkeleton: true, EmptyState: true }

describe('IocView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockIocsList.mockResolvedValue({
      data: FAKE_IOCS,
      pagination: { totalItems: 2 },
    })
    mockIocsCreate.mockResolvedValue({ data: {} })
    mockIocsDelete.mockResolvedValue({})
    vi.stubGlobal('confirm', vi.fn().mockReturnValue(true))
  })

  it('renders the IOCs heading', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('Threat Intelligence')
    expect(w.text()).toContain('IOCs')
  })

  it('calls iocsApi.list on mount', async () => {
    mount(IocView, { global: { stubs } })
    await flushPromises()
    expect(mockIocsList).toHaveBeenCalledOnce()
  })

  it('renders IOC values after load', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('10.0.0.99')
    expect(w.text()).toContain('deadbeef1234567890abcdef')
  })

  it('renders total IOC count', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('2')
  })

  it('renders Add IOC button', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('Add IOC')
  })

  it('renders IOC type badges', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('IPV4')
    expect(w.text()).toContain('SHA256')
  })

  it('addIoc does nothing when value is empty', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).form.value = ''
    await (w.vm as any).addIoc()
    expect(mockIocsCreate).not.toHaveBeenCalled()
  })

  it('addIoc does nothing when value is only whitespace', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).form.value = '   '
    await (w.vm as any).addIoc()
    expect(mockIocsCreate).not.toHaveBeenCalled()
  })

  it('addIoc calls iocsApi.create with form data', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).form.value = '1.2.3.4'
    ;(w.vm as any).form.type = 'IPV4'
    ;(w.vm as any).form.name = 'Test IP'
    ;(w.vm as any).form.description = 'Malicious'
    await (w.vm as any).addIoc()
    await flushPromises()
    expect(mockIocsCreate).toHaveBeenCalledWith({
      type: 'IPV4',
      value: '1.2.3.4',
      name: 'Test IP',
      description: 'Malicious',
    })
  })

  it('addIoc uses value as name when name is empty', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).form.value = '5.5.5.5'
    ;(w.vm as any).form.name = ''
    await (w.vm as any).addIoc()
    await flushPromises()
    expect(mockIocsCreate).toHaveBeenCalledWith(expect.objectContaining({ name: '5.5.5.5' }))
  })

  it('addIoc resets form after success', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).showAdd = true
    ;(w.vm as any).form.value = '1.2.3.4'
    ;(w.vm as any).form.type = 'IPV4'
    await (w.vm as any).addIoc()
    await flushPromises()
    expect((w.vm as any).form.value).toBe('')
    expect((w.vm as any).form.type).toBe('IPV4')
    expect((w.vm as any).showAdd).toBe(false)
  })

  it('addIoc refreshes list after success', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    mockIocsList.mockClear()
    ;(w.vm as any).form.value = '9.9.9.9'
    await (w.vm as any).addIoc()
    await flushPromises()
    expect(mockIocsList).toHaveBeenCalled()
  })

  it('toggleSelect adds IOC to selected set', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).toggleSelect('ioc1')
    expect((w.vm as any).selected.has('ioc1')).toBe(true)
  })

  it('toggleSelect removes IOC when already selected', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).toggleSelect('ioc1')
    ;(w.vm as any).toggleSelect('ioc1')
    expect((w.vm as any).selected.has('ioc1')).toBe(false)
  })

  it('toggleAll selects all when none selected', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).toggleAll()
    expect((w.vm as any).selected.size).toBe(2)
  })

  it('toggleAll deselects all when all are selected', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).toggleAll()
    ;(w.vm as any).toggleAll()
    expect((w.vm as any).selected.size).toBe(0)
  })

  it('deleteSelected does nothing when nothing is selected', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).deleteSelected()
    expect(mockIocsDelete).not.toHaveBeenCalled()
  })

  it('deleteSelected does nothing when confirm is cancelled', async () => {
    vi.stubGlobal('confirm', vi.fn().mockReturnValue(false))
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).toggleSelect('ioc1')
    await (w.vm as any).deleteSelected()
    expect(mockIocsDelete).not.toHaveBeenCalled()
  })

  it('deleteSelected calls iocsApi.delete with selected IDs', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).toggleSelect('ioc1')
    ;(w.vm as any).toggleSelect('ioc2')
    await (w.vm as any).deleteSelected()
    await flushPromises()
    expect(mockIocsDelete).toHaveBeenCalledWith(['ioc1', 'ioc2'])
  })

  it('deleteSelected removes items from list after deletion', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).toggleSelect('ioc1')
    await (w.vm as any).deleteSelected()
    await flushPromises()
    expect((w.vm as any).items).toHaveLength(1)
    expect((w.vm as any).items[0].uuid).toBe('ioc2')
  })

  it('deleteSelected clears selection after deletion', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).toggleSelect('ioc1')
    await (w.vm as any).deleteSelected()
    await flushPromises()
    expect((w.vm as any).selected.size).toBe(0)
  })

  it('deleteSelected updates total after deletion', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).toggleAll()
    await (w.vm as any).deleteSelected()
    await flushPromises()
    expect((w.vm as any).total).toBe(0)
  })

  it('fetchList uses pagination totalItems when available', async () => {
    mockIocsList.mockResolvedValueOnce({ data: FAKE_IOCS, pagination: { totalItems: 100 } })
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).total).toBe(100)
  })

  it('fetchList falls back to data.length when pagination absent', async () => {
    mockIocsList.mockResolvedValueOnce({ data: FAKE_IOCS })
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).total).toBe(2)
  })

  // ── DOM trigger tests ──────────────────────────────────────────────────────

  it('Add IOC button toggles showAdd via DOM click', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).showAdd).toBe(false)
    const addBtn = w.findAll('button').find(b => b.text().includes('Add IOC'))
    await addBtn!.trigger('click')
    expect((w.vm as any).showAdd).toBe(true)
  })

  it('Cancel button hides add form via DOM click', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).showAdd = true
    await w.vm.$nextTick()
    const cancelBtn = w.findAll('button').find(b => b.text() === 'Cancel')
    await cancelBtn!.trigger('click')
    expect((w.vm as any).showAdd).toBe(false)
  })

  it('Submit Add IOC button calls addIoc via DOM click', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).showAdd = true
    ;(w.vm as any).form.value = '1.1.1.1'
    await w.vm.$nextTick()
    const submitBtns = w.findAll('button').filter(b => b.text().includes('Add IOC'))
    // The second "Add IOC" button is the submit button inside the form
    const submitBtn = submitBtns[submitBtns.length - 1]
    await submitBtn.trigger('click')
    await flushPromises()
    expect(mockIocsCreate).toHaveBeenCalledWith(expect.objectContaining({ value: '1.1.1.1' }))
  })

  it('header checkbox triggers toggleAll via DOM change', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    const headerCheckbox = w.find('thead input[type="checkbox"]')
    await headerCheckbox.trigger('change')
    expect((w.vm as any).selected.size).toBe(2)
  })

  it('row checkbox triggers toggleSelect via DOM change', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    const rowCheckboxes = w.findAll('tbody input[type="checkbox"]')
    await rowCheckboxes[0].trigger('change')
    expect((w.vm as any).selected.has('ioc1')).toBe(true)
  })

  it('Delete button triggers deleteSelected via DOM click', async () => {
    const w = mount(IocView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).toggleSelect('ioc1')
    await w.vm.$nextTick()
    const deleteBtn = w.findAll('button').find(b => b.text().includes('Delete'))
    await deleteBtn!.trigger('click')
    await flushPromises()
    expect(mockIocsDelete).toHaveBeenCalledWith(['ioc1'])
  })
})
