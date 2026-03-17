import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import IocView from '../IocView.vue'

const mockIocsList = vi.hoisted(() => vi.fn())
const mockIocsCreate = vi.hoisted(() => vi.fn())
const mockIocsDelete = vi.hoisted(() => vi.fn())

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

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

describe('IocView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockIocsList.mockResolvedValue({
      data: FAKE_IOCS,
      pagination: { totalItems: 2 },
    })
  })

  it('renders without error', async () => {
    const w = shallowMount(IocView)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the IOCs heading', async () => {
    const w = shallowMount(IocView)
    await flushPromises()
    expect(w.text()).toContain('Threat Intelligence')
    expect(w.text()).toContain('IOCs')
  })

  it('calls iocsApi.list on mount', async () => {
    shallowMount(IocView)
    await flushPromises()
    expect(mockIocsList).toHaveBeenCalledOnce()
  })

  it('renders IOC values after load', async () => {
    const w = shallowMount(IocView)
    await flushPromises()
    expect(w.text()).toContain('10.0.0.99')
    expect(w.text()).toContain('deadbeef1234567890abcdef')
  })

  it('renders total IOC count', async () => {
    const w = shallowMount(IocView)
    await flushPromises()
    expect(w.text()).toContain('2')
  })

  it('renders Add IOC button', async () => {
    const w = shallowMount(IocView)
    await flushPromises()
    expect(w.text()).toContain('Add IOC')
  })

  it('shows add form when Add IOC is clicked', async () => {
    const w = shallowMount(IocView)
    await flushPromises()
    expect(w.text()).not.toContain('Add Indicator of Compromise')
    // Click the Add IOC button (the last btn-primary)
    const buttons = w.findAll('.btn-primary')
    await buttons[buttons.length - 1].trigger('click')
    expect(w.text()).toContain('Add Indicator of Compromise')
  })

  it('renders IOC type badges', async () => {
    const w = shallowMount(IocView)
    await flushPromises()
    expect(w.text()).toContain('IPV4')
    expect(w.text()).toContain('SHA256')
  })
})
