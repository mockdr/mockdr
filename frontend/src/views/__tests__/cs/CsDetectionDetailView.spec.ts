import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

const mockGetEntities = vi.hoisted(() => vi.fn())

const mockUpdate = vi.hoisted(() => vi.fn())

vi.mock('../../../api/crowdstrike', () => ({
  ensureCsAuth: vi.fn().mockResolvedValue(undefined),
  csDetectionsApi: {
    getEntities: mockGetEntities,
    update: mockUpdate,
  },
}))

import CsDetectionDetailView from '@/views/cs/CsDetectionDetailView.vue'
import { ensureCsAuth, csDetectionsApi } from '@/api/crowdstrike'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/crowdstrike/detections', component: { template: '<div />' } },
    { path: '/crowdstrike/detections/:id', component: CsDetectionDetailView },
  ],
})

const stubs = { LoadingSkeleton: true }

describe('CsDetectionDetailView', () => {
  beforeEach(async () => {
    await router.push('/crowdstrike/detections/test-detection-id')
    await router.isReady()
    vi.clearAllMocks()
    mockGetEntities.mockResolvedValue({
      resources: [
        {
          composite_id: 'test-detection-id',
          status: 'new',
          max_severity: 85,
          max_severity_displayname: 'Critical',
          max_confidence: 90,
          first_behavior: '2025-01-01T10:00:00Z',
          last_behavior: '2025-01-01T11:00:00Z',
          created_timestamp: '2025-01-01T09:00:00Z',
          date_updated: '2025-01-02T09:00:00Z',
          assigned_to_name: 'Alice',
          behaviors: [
            {
              behavior_id: 'bhv-1',
              filename: 'malware.exe',
              filepath: 'C:\\temp\\malware.exe',
              scenario: 'malware-execution',
              severity: 85,
              confidence: 80,
              timestamp: '2025-01-01T10:00:00Z',
              user_name: 'ADMIN',
              tactic: 'Execution',
              tactic_id: 'TA0002',
              technique: 'Command and Scripting Interpreter',
              technique_id: 'T1059',
              cmdline: 'cmd.exe /c whoami',
              sha256: 'abc123',
              md5: 'def456',
              ioc_type: 'hash',
              ioc_value: 'abc123',
            },
          ],
          device: {
            device_id: 'dev-1',
            hostname: 'WKSTN-001',
            platform_name: 'Windows',
            os_version: 'Windows 11',
            external_ip: '1.2.3.4',
            status: 'normal',
            agent_version: '7.0.0',
          },
        },
      ],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    mockUpdate.mockResolvedValue({ resources: [], errors: [] })
  })

  it('calls ensureCsAuth and getEntities on mount', async () => {
    mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(ensureCsAuth).toHaveBeenCalled()
    expect(csDetectionsApi.getEntities).toHaveBeenCalledWith(['test-detection-id'])
  })

  it('renders detection composite_id after loading', async () => {
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('test-detection-id')
  })

  it('renders severity display name', async () => {
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('Critical')
  })

  it('renders detection status badge', async () => {
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('new')
  })

  it('renders assigned_to_name in detection summary', async () => {
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('Alice')
  })

  it('renders WKSTN-001 hostname in device info', async () => {
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('WKSTN-001')
  })

  it('sets loading to false after fetch', async () => {
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('severityBadgeClass returns red for severity >= 80', () => {
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).severityBadgeClass(80)).toBe('bg-red-500/15 text-red-400')
    expect((wrapper.vm as any).severityBadgeClass(100)).toBe('bg-red-500/15 text-red-400')
  })

  it('severityBadgeClass returns orange for severity 60-79', () => {
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).severityBadgeClass(60)).toBe('bg-orange-500/15 text-orange-400')
  })

  it('severityBadgeClass returns yellow for severity 40-59', () => {
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).severityBadgeClass(40)).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('severityBadgeClass returns blue for severity 20-39', () => {
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).severityBadgeClass(20)).toBe('bg-blue-500/15 text-blue-400')
  })

  it('severityBadgeClass returns gray for severity < 20', () => {
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).severityBadgeClass(10)).toBe('bg-gray-500/15 text-gray-400')
  })

  it('statusBadgeClass returns correct class for each status', () => {
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    const vm = wrapper.vm as any
    expect(vm.statusBadgeClass('new')).toBe('bg-blue-500/15 text-blue-400')
    expect(vm.statusBadgeClass('in_progress')).toBe('bg-yellow-500/15 text-yellow-400')
    expect(vm.statusBadgeClass('true_positive')).toBe('bg-red-500/15 text-red-400')
    expect(vm.statusBadgeClass('false_positive')).toBe('bg-green-500/15 text-green-400')
    expect(vm.statusBadgeClass('closed')).toBe('bg-gray-500/15 text-gray-400')
    expect(vm.statusBadgeClass('unknown')).toBe('bg-gray-500/15 text-gray-400')
  })

  it('updateStatus calls csDetectionsApi.update with new status then re-fetches', async () => {
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    vi.clearAllMocks()
    await (wrapper.vm as any).updateStatus('in_progress')
    await flushPromises()
    expect(csDetectionsApi.update).toHaveBeenCalledWith(['test-detection-id'], { status: 'in_progress' })
    expect(csDetectionsApi.getEntities).toHaveBeenCalledWith(['test-detection-id'])
  })

  it('updateStatus updates detection from re-fetched entity', async () => {
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    mockGetEntities.mockResolvedValueOnce({
      resources: [
        {
          composite_id: 'test-detection-id',
          status: 'in_progress',
          max_severity: 85,
          max_severity_displayname: 'Critical',
          behaviors: [],
          device: { hostname: 'WKSTN-001' },
        },
      ],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    await (wrapper.vm as any).updateStatus('in_progress')
    await flushPromises()
    expect((wrapper.vm as any).detection.status).toBe('in_progress')
  })

  it('updateStatus does nothing when detection is null', async () => {
    mockGetEntities.mockResolvedValueOnce({
      resources: [],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).detection).toBeNull()
    vi.clearAllMocks()
    await (wrapper.vm as any).updateStatus('closed')
    expect(csDetectionsApi.update).not.toHaveBeenCalled()
  })

  it('sets updating to false after updateStatus completes', async () => {
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    await (wrapper.vm as any).updateStatus('closed')
    await flushPromises()
    expect((wrapper.vm as any).updating).toBe(false)
  })

  it('activeTab defaults to overview', async () => {
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).activeTab).toBe('overview')
  })

  it('switching activeTab to behaviors shows behavior content', async () => {
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    ;(wrapper.vm as any).activeTab = 'behaviors'
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('malware-execution')
  })

  it('switching activeTab to device shows device information', async () => {
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    ;(wrapper.vm as any).activeTab = 'device'
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Device Information')
  })

  it('shows "Detection not found" when getEntities returns empty resources', async () => {
    mockGetEntities.mockResolvedValueOnce({
      resources: [],
      meta: { query_time: 0, powered_by: '', trace_id: '' },
      errors: [],
    })
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('Detection not found')
  })

  it('renders behavior cmdline when present', async () => {
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    ;(wrapper.vm as any).activeTab = 'behaviors'
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('cmd.exe /c whoami')
  })

  it('renders SHA256 hash when present in behavior', async () => {
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    await flushPromises()
    ;(wrapper.vm as any).activeTab = 'behaviors'
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('abc123')
  })

  it('TABS constant contains overview, behaviors, and device tabs', () => {
    const wrapper = mount(CsDetectionDetailView, { global: { plugins: [router], stubs } })
    const vm = wrapper.vm as any
    const tabIds = vm.TABS.map((t: { id: string }) => t.id)
    expect(tabIds).toContain('overview')
    expect(tabIds).toContain('behaviors')
    expect(tabIds).toContain('device')
  })
})
