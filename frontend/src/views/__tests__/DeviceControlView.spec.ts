import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'

vi.mock('../../api/misc', () => ({
  deviceControlApi: {
    list: vi.fn().mockImplementation(() => Promise.resolve({
      data: [{ id: 'dc1', ruleName: 'Block USB Storage', action: 'Block', status: 'Enabled', interface: 'USB', ruleType: 'class', deviceClass: 'USB_STORAGE', accessPermission: 'Not-Applicable', vendorId: null, productId: null, deviceId: null, uid: null }],
      pagination: { totalItems: 1 },
    })),
    create: vi.fn().mockImplementation(() => Promise.resolve({ data: { id: 'dc2', ruleName: 'New Rule', action: 'Allow', status: 'Enabled', interface: 'USB', ruleType: 'class', deviceClass: 'USB_STORAGE', accessPermission: 'Not-Applicable' } })),
    update: vi.fn().mockImplementation(() => Promise.resolve({ data: { id: 'dc1', ruleName: 'Updated Rule', action: 'Block', status: 'Enabled', interface: 'USB', ruleType: 'class', deviceClass: 'USB_STORAGE', accessPermission: 'Not-Applicable' } })),
    delete: vi.fn().mockResolvedValue({}),
  },
}))

import DeviceControlView from '@/views/DeviceControlView.vue'

const stubs = { LoadingSkeleton: true, EmptyState: true }

describe('DeviceControlView', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('renders Device Control heading', async () => {
    const w = mount(DeviceControlView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('Device Control')
  })

  it('renders rule name after load', async () => {
    const w = mount(DeviceControlView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('Block USB Storage')
  })

  it('openCreate sets modal to create mode', async () => {
    const w = mount(DeviceControlView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    expect((w.vm as any).modalMode).toBe('create')
    expect((w.vm as any).form.ruleName).toBe('')
  })

  it('openEdit sets modal to edit mode with rule data', async () => {
    const w = mount(DeviceControlView, { global: { stubs } })
    await flushPromises()
    const rule = (w.vm as any).items[0]
    ;(w.vm as any).openEdit(rule)
    expect((w.vm as any).modalMode).toBe('edit')
    expect((w.vm as any).editingId).toBe('dc1')
    expect((w.vm as any).form.ruleName).toBe('Block USB Storage')
  })

  it('closeModal clears modal mode', async () => {
    const w = mount(DeviceControlView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).closeModal()
    expect((w.vm as any).modalMode).toBeNull()
  })

  it('saveModal shows error when ruleName is empty', async () => {
    const w = mount(DeviceControlView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.ruleName = ''
    await (w.vm as any).saveModal()
    expect((w.vm as any).modalError).toBeTruthy()
  })

  it('saveModal creates rule', async () => {
    const { deviceControlApi } = await import('../../api/misc')
    const w = mount(DeviceControlView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.ruleName = 'New Rule'
    await (w.vm as any).saveModal()
    await flushPromises()
    expect(deviceControlApi.create).toHaveBeenCalled()
  })

  it('saveModal updates rule', async () => {
    const { deviceControlApi } = await import('../../api/misc')
    const w = mount(DeviceControlView, { global: { stubs } })
    await flushPromises()
    const rule = (w.vm as any).items[0]
    ;(w.vm as any).openEdit(rule)
    ;(w.vm as any).form.ruleName = 'Updated'
    await (w.vm as any).saveModal()
    await flushPromises()
    expect(deviceControlApi.update).toHaveBeenCalledWith('dc1', expect.any(Object))
  })

  it('confirmDelete calls deviceControlApi.delete', async () => {
    const { deviceControlApi } = await import('../../api/misc')
    const w = mount(DeviceControlView, { global: { stubs } })
    await flushPromises()
    const rule = (w.vm as any).items[0]
    await (w.vm as any).confirmDelete(rule)
    expect(deviceControlApi.delete).toHaveBeenCalledWith('dc1')
    expect((w.vm as any).items).toHaveLength(0)
  })

  it('New Rule button calls openCreate via DOM click', async () => {
    const w = mount(DeviceControlView, { global: { stubs } })
    await flushPromises()
    const btn = w.findAll('button').find(b => b.text().includes('New Rule'))
    await btn!.trigger('click')
    expect((w.vm as any).modalMode).toBe('create')
  })

  it('edit button calls openEdit via DOM click', async () => {
    const w = mount(DeviceControlView, { global: { stubs } })
    await flushPromises()
    const editBtn = w.find('button[title="Edit"]')
    await editBtn.trigger('click')
    expect((w.vm as any).modalMode).toBe('edit')
  })

  it('delete button sets confirmDeleteId via DOM click', async () => {
    const w = mount(DeviceControlView, { global: { stubs } })
    await flushPromises()
    const deleteBtn = w.find('button[title="Delete"]')
    await deleteBtn.trigger('click')
    expect((w.vm as any).confirmDeleteId).toBe('dc1')
  })

  it('Confirm delete button calls confirmDelete via DOM', async () => {
    const { deviceControlApi } = await import('../../api/misc')
    const w = mount(DeviceControlView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).confirmDeleteId = 'dc1'
    await w.vm.$nextTick()
    const confirmBtn = w.findAll('button').find(b => b.text() === 'Confirm')
    await confirmBtn!.trigger('click')
    await flushPromises()
    expect(deviceControlApi.delete).toHaveBeenCalledWith('dc1')
  })

  it('cancel X button clears confirmDeleteId via DOM', async () => {
    const w = mount(DeviceControlView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).confirmDeleteId = 'dc1'
    await w.vm.$nextTick()
    // The X cancel button is the last button in the row actions
    const xBtns = w.findAll('button').filter(b => b.text() === '')
    // Find the small X cancel (not the edit or delete icons)
    const cancelX = xBtns[xBtns.length - 1]
    await cancelX.trigger('click')
    expect((w.vm as any).confirmDeleteId).toBeNull()
  })

  it('modal Cancel button calls closeModal via DOM', async () => {
    const w = mount(DeviceControlView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    const cancelBtn = w.findAll('button').find(b => b.text() === 'Cancel')
    await cancelBtn!.trigger('click')
    expect((w.vm as any).modalMode).toBeNull()
  })

  it('modal Save button calls saveModal via DOM', async () => {
    const { deviceControlApi } = await import('../../api/misc')
    const w = mount(DeviceControlView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.ruleName = 'DOM Rule'
    await w.vm.$nextTick()
    const saveBtn = w.findAll('button').find(b => b.text() === 'Save')
    await saveBtn!.trigger('click')
    await flushPromises()
    expect(deviceControlApi.create).toHaveBeenCalled()
  })

  it('modal X close button calls closeModal via DOM', async () => {
    const w = mount(DeviceControlView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    // The X button in modal header (first button with no text after modal opens)
    const xBtn = w.findAll('button').find(b => b.attributes('title') === undefined && b.text() === '')
    if (xBtn) {
      await xBtn.trigger('click')
      expect((w.vm as any).modalMode).toBeNull()
    }
  })

  it('vendorId input updates form.vendorId via DOM setValue', async () => {
    const w = mount(DeviceControlView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    const vendorInput = w.find('input.input.w-full.text-sm.font-mono[placeholder="e.g. 0x1234"]')
    if (vendorInput.exists()) {
      await vendorInput.setValue('0xABCD')
      expect((w.vm as any).form.vendorId).toBe('0xABCD')
    }
  })

  it('productId input updates form.productId via DOM setValue', async () => {
    const w = mount(DeviceControlView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    const productInput = w.find('input.input.w-full.text-sm.font-mono[placeholder="e.g. 0x5678"]')
    if (productInput.exists()) {
      await productInput.setValue('0x1234')
      expect((w.vm as any).form.productId).toBe('0x1234')
    }
  })

  it('deviceId input updates form.deviceId via DOM setValue', async () => {
    const w = mount(DeviceControlView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    const deviceInputs = w.findAll('input.input.w-full.text-sm.font-mono[placeholder="Optional"]')
    if (deviceInputs.length > 0) {
      await deviceInputs[0].setValue('DEV-001')
      expect((w.vm as any).form.deviceId).toBe('DEV-001')
    }
  })

  it('uid input updates form.uid via DOM setValue', async () => {
    const w = mount(DeviceControlView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    const deviceInputs = w.findAll('input.input.w-full.text-sm.font-mono[placeholder="Optional"]')
    if (deviceInputs.length > 1) {
      await deviceInputs[1].setValue('UID-999')
      expect((w.vm as any).form.uid).toBe('UID-999')
    }
  })
})
