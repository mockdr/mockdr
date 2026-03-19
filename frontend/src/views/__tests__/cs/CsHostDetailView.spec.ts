import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

const mockGetEntities = vi.hoisted(() => vi.fn())

vi.mock('../../../api/crowdstrike', () => ({
  ensureCsAuth: vi.fn().mockResolvedValue(undefined),
  csHostsApi: {
    getEntities: mockGetEntities,
    action: vi.fn().mockResolvedValue({ resources: [], errors: [] }),
  },
}))

import CsHostDetailView from '@/views/cs/CsHostDetailView.vue'
import { ensureCsAuth, csHostsApi } from '@/api/crowdstrike'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/crowdstrike/hosts', component: { template: '<div />' } },
    { path: '/crowdstrike/hosts/:id', component: CsHostDetailView },
  ],
})

const stubs = { LoadingSkeleton: true }

describe('CsHostDetailView', () => {
  beforeEach(async () => {
    await router.push('/crowdstrike/hosts/test-host-id')
    await router.isReady()
    vi.clearAllMocks()
    mockGetEntities.mockResolvedValue({
      resources: [
        {
          device_id: 'test-host-id',
          hostname: 'WKSTN-001',
          status: 'normal',
          platform_name: 'Windows',
          os_version: 'Windows 11',
          agent_version: '7.0.0',
          cid: 'cid-abc',
          local_ip: '10.0.0.1',
          external_ip: '203.0.113.5',
          mac_address: '00:11:22:33:44:55',
          machine_domain: 'CORP',
          product_type_desc: 'Workstation',
          serial_number: 'SN-12345',
          first_seen: '2025-01-01T00:00:00Z',
          last_seen: '2025-06-01T12:00:00Z',
          groups: ['group-abc'],
          tags: ['tag1', 'tag2'],
          system_manufacturer: 'Dell Inc.',
          system_product_name: 'Latitude 5520',
          chassis_type: 'Notebook',
          platform_id: '0',
          provision_status: 'Provisioned',
          reduced_functionality_mode: 'no',
          detection_suppression_status: 'disabled',
          modified_timestamp: '2025-06-01T00:00:00Z',
          site_name: 'Main',
        },
      ],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
  })

  it('calls ensureCsAuth and getEntities on mount', async () => {
    mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(ensureCsAuth).toHaveBeenCalled()
    expect(csHostsApi.getEntities).toHaveBeenCalledWith(['test-host-id'])
  })

  it('renders hostname after loading', async () => {
    const wrapper = mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('WKSTN-001')
  })

  it('renders host status badge', async () => {
    const wrapper = mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('normal')
  })

  it('renders platform name', async () => {
    const wrapper = mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('Windows')
  })

  it('sets loading to false after mount', async () => {
    const wrapper = mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('activeTab defaults to overview', async () => {
    const wrapper = mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).activeTab).toBe('overview')
  })

  it('platformColor returns correct class for Windows', () => {
    const wrapper = mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).platformColor('Windows')).toBe('bg-red-500/20 text-red-400')
  })

  it('platformColor returns correct class for Mac', () => {
    const wrapper = mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).platformColor('Mac')).toBe('bg-orange-500/20 text-orange-400')
  })

  it('platformColor returns correct class for Linux', () => {
    const wrapper = mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).platformColor('Linux')).toBe('bg-yellow-500/20 text-yellow-400')
  })

  it('platformColor returns default class for unknown platform', () => {
    const wrapper = mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).platformColor('FreeBSD')).toBe('bg-gray-500/20 text-gray-400')
  })

  it('TABS contains overview, network, and system', () => {
    const wrapper = mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    const tabIds = (wrapper.vm as any).TABS.map((t: { id: string }) => t.id)
    expect(tabIds).toContain('overview')
    expect(tabIds).toContain('network')
    expect(tabIds).toContain('system')
  })

  it('overview tab shows device information section', async () => {
    const wrapper = mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('Device Information')
  })

  it('overview tab shows host groups when present', async () => {
    const wrapper = mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('group-abc')
  })

  it('switching to network tab shows Network Configuration section', async () => {
    const wrapper = mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    ;(wrapper.vm as any).activeTab = 'network'
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Network Configuration')
  })

  it('network tab renders local and external IPs', async () => {
    const wrapper = mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    ;(wrapper.vm as any).activeTab = 'network'
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('10.0.0.1')
    expect(wrapper.text()).toContain('203.0.113.5')
  })

  it('switching to system tab shows System Hardware section', async () => {
    const wrapper = mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    ;(wrapper.vm as any).activeTab = 'system'
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('System Hardware')
  })

  it('system tab renders system manufacturer', async () => {
    const wrapper = mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    ;(wrapper.vm as any).activeTab = 'system'
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Dell Inc.')
  })

  it('shows tags when host has tags', async () => {
    const wrapper = mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('tag1')
    expect(wrapper.text()).toContain('tag2')
  })

  it('shows "Host not found" when getEntities returns empty resources', async () => {
    mockGetEntities.mockResolvedValueOnce({
      resources: [],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    const wrapper = mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('Host not found')
  })

  it('host ref is null when no entity returned', async () => {
    mockGetEntities.mockResolvedValueOnce({
      resources: [],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    const wrapper = mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).host).toBeNull()
  })

  it('renders serial number in overview tab', async () => {
    const wrapper = mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('SN-12345')
  })

  it('renders contained status host correctly', async () => {
    mockGetEntities.mockResolvedValueOnce({
      resources: [
        {
          device_id: 'test-host-id',
          hostname: 'CONTAINED-HOST',
          status: 'contained',
          platform_name: 'Linux',
          groups: [],
          tags: [],
        },
      ],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    const wrapper = mount(CsHostDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('contained')
  })
})
