import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

const mockEndpointsList = vi.hoisted(() => vi.fn())
const mockIsolate = vi.hoisted(() => vi.fn())
const mockUnisolate = vi.hoisted(() => vi.fn())
const mockScan = vi.hoisted(() => vi.fn())

vi.mock('../../../api/cortex', () => ({
  xdrEndpointsApi: {
    list: mockEndpointsList,
    isolate: mockIsolate,
    unisolate: mockUnisolate,
    scan: mockScan,
  },
}))

vi.mock('../../../utils/formatters', () => ({
  formatEpoch: vi.fn((v) => `${v}`),
}))

import XdrEndpointDetailView from '@/views/xdr/XdrEndpointDetailView.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/xdr/endpoints/:id', component: { template: '<div />' } },
  ],
})

const stubs = { LoadingSkeleton: true }

const FAKE_ENDPOINT = {
  endpoint_id: 'ep-1',
  endpoint_name: 'WKSTN-001',
  endpoint_status: 'CONNECTED',
  os_type: 'AGENT_OS_WINDOWS',
  ip: ['10.0.0.1'],
  users: ['jdoe'],
  alias: 'ws01',
  content_version: '1.0',
  install_date: '2025-01-01',
  last_seen: 1700000000000,
  endpoint_version: '7.0.0',
  is_isolated: 'AGENT_UNISOLATED',
}

describe('XdrEndpointDetailView', () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    mockEndpointsList.mockResolvedValue({ reply: { endpoints: [FAKE_ENDPOINT], total_count: 1 } })
    mockIsolate.mockResolvedValue(undefined)
    mockUnisolate.mockResolvedValue(undefined)
    mockScan.mockResolvedValue(undefined)
    await router.push('/xdr/endpoints/ep-1')
    await router.isReady()
  })

  it('renders endpoint name after loading', async () => {
    const wrapper = mount(XdrEndpointDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('WKSTN-001')
  })

  it('calls xdrEndpointsApi.list on mount with endpoint id filter', async () => {
    mount(XdrEndpointDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(mockEndpointsList).toHaveBeenCalledWith(
      expect.arrayContaining([expect.objectContaining({ field: 'endpoint_id', value: ['ep-1'] })])
    )
  })

  it('sets loading to false after data loads', async () => {
    const wrapper = mount(XdrEndpointDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('statusBadgeClass returns green for connected', () => {
    const wrapper = mount(XdrEndpointDetailView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusBadgeClass('connected')).toContain('green')
  })

  it('statusBadgeClass returns red for disconnected', () => {
    const wrapper = mount(XdrEndpointDetailView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusBadgeClass('disconnected')).toContain('red')
  })

  it('statusBadgeClass returns gray for lost', () => {
    const wrapper = mount(XdrEndpointDetailView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusBadgeClass('lost')).toContain('gray')
  })

  it('statusBadgeClass returns gray for unknown status', () => {
    const wrapper = mount(XdrEndpointDetailView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).statusBadgeClass('unknown')).toContain('gray')
  })

  it('isolationBadgeClass returns red for isolated', () => {
    const wrapper = mount(XdrEndpointDetailView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).isolationBadgeClass('isolated')).toContain('red')
  })

  it('isolationBadgeClass returns green for unisolated', () => {
    const wrapper = mount(XdrEndpointDetailView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).isolationBadgeClass('unisolated')).toContain('green')
  })

  it('isolationBadgeClass returns green for not_isolated', () => {
    const wrapper = mount(XdrEndpointDetailView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).isolationBadgeClass('not_isolated')).toContain('green')
  })

  it('performAction isolate calls xdrEndpointsApi.isolate', async () => {
    const wrapper = mount(XdrEndpointDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    await (wrapper.vm as any).performAction('isolate')
    await flushPromises()
    expect(mockIsolate).toHaveBeenCalledWith('ep-1')
  })

  it('performAction unisolate calls xdrEndpointsApi.unisolate', async () => {
    const wrapper = mount(XdrEndpointDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    await (wrapper.vm as any).performAction('unisolate')
    await flushPromises()
    expect(mockUnisolate).toHaveBeenCalledWith('ep-1')
  })

  it('performAction scan calls xdrEndpointsApi.scan', async () => {
    const wrapper = mount(XdrEndpointDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    await (wrapper.vm as any).performAction('scan')
    await flushPromises()
    expect(mockScan).toHaveBeenCalledWith('ep-1')
  })

  it('performAction does nothing when endpoint is null', async () => {
    mockEndpointsList.mockResolvedValueOnce({ reply: { endpoints: [] } })
    const wrapper = mount(XdrEndpointDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    mockIsolate.mockClear()
    await (wrapper.vm as any).performAction('isolate')
    expect(mockIsolate).not.toHaveBeenCalled()
  })

  it('performAction sets actionLoading to false after completion', async () => {
    const wrapper = mount(XdrEndpointDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    await (wrapper.vm as any).performAction('scan')
    await flushPromises()
    expect((wrapper.vm as any).actionLoading).toBe(false)
  })

  it('endpoint is null when API returns empty endpoints', async () => {
    mockEndpointsList.mockResolvedValueOnce({ reply: { endpoints: [] } })
    const wrapper = mount(XdrEndpointDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).endpoint).toBeNull()
  })

  it('Isolate button triggers performAction via DOM click', async () => {
    const wrapper = mount(XdrEndpointDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    mockIsolate.mockClear()
    const isolateBtn = wrapper.findAll('button').find(b => b.text().includes('Isolate'))
    await isolateBtn!.trigger('click')
    await flushPromises()
    expect(mockIsolate).toHaveBeenCalled()
  })

  it('Unisolate button triggers performAction via DOM click', async () => {
    const wrapper = mount(XdrEndpointDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    mockUnisolate.mockClear()
    const unisolateBtn = wrapper.findAll('button').find(b => b.text().includes('Unisolate'))
    await unisolateBtn!.trigger('click')
    await flushPromises()
    expect(mockUnisolate).toHaveBeenCalled()
  })

  it('Scan button triggers performAction via DOM click', async () => {
    const wrapper = mount(XdrEndpointDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    mockScan.mockClear()
    const scanBtn = wrapper.findAll('button').find(b => b.text().includes('Scan') && !b.text().includes('isolate'))
    await scanBtn!.trigger('click')
    await flushPromises()
    expect(mockScan).toHaveBeenCalled()
  })
})
