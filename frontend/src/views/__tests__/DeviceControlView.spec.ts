import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import DeviceControlView from '../DeviceControlView.vue'

const mockDeviceControlList = vi.hoisted(() => vi.fn())

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../api/misc', () => ({
  deviceControlApi: {
    list: mockDeviceControlList,
    create: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
}))

const FAKE_RULES = [
  {
    id: 'dc1', ruleName: 'Block USB Storage', action: 'Block', status: 'Enabled',
    interface: 'USB', ruleType: 'class', deviceClass: 'USB_STORAGE',
    accessPermission: 'Not-Applicable', vendorId: null, productId: null,
    deviceId: null, uid: null, editable: true,
  },
  {
    id: 'dc2', ruleName: 'Allow Keyboard', action: 'Allow', status: 'Enabled',
    interface: 'USB', ruleType: 'vendorId', deviceClass: 'USB_STORAGE',
    accessPermission: 'Read-Write', vendorId: '0x1234', productId: null,
    deviceId: null, uid: null, editable: true,
  },
]

describe('DeviceControlView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockDeviceControlList.mockResolvedValue({
      data: FAKE_RULES,
      pagination: { totalItems: 2 },
    })
  })

  it('renders without error', async () => {
    const w = shallowMount(DeviceControlView)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the Device Control heading', async () => {
    const w = shallowMount(DeviceControlView)
    await flushPromises()
    expect(w.text()).toContain('Device Control')
  })

  it('calls deviceControlApi.list on mount', async () => {
    shallowMount(DeviceControlView)
    await flushPromises()
    expect(mockDeviceControlList).toHaveBeenCalledOnce()
  })

  it('renders rule names after load', async () => {
    const w = shallowMount(DeviceControlView)
    await flushPromises()
    expect(w.text()).toContain('Block USB Storage')
    expect(w.text()).toContain('Allow Keyboard')
  })

  it('renders total rules count', async () => {
    const w = shallowMount(DeviceControlView)
    await flushPromises()
    expect(w.text()).toContain('2')
  })

  it('renders New Rule button', async () => {
    const w = shallowMount(DeviceControlView)
    await flushPromises()
    expect(w.text()).toContain('New Rule')
  })

  it('renders vendor ID when present', async () => {
    const w = shallowMount(DeviceControlView)
    await flushPromises()
    expect(w.text()).toContain('0x1234')
  })
})
