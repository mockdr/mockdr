import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/cortex', () => ({
  xdrIncidentsApi: {
    getExtraData: vi.fn().mockResolvedValue({
      reply: {
        incident: {
          incident_id: 'test-inc-1',
          incident_name: 'Critical Incident',
          description: 'Ransomware detected on multiple hosts',
          status: 'new',
          severity: 'critical',
          creation_time: 1700000000000,
          modification_time: 1700001000000,
          alert_count: 5,
          hosts: ['WKSTN-001', 'WKSTN-002'],
          users: ['admin', 'jdoe'],
          rule_based_score: 95,
          manual_severity: null,
          starred: true,
          assigned_user_pretty_name: 'Alice Admin',
          assigned_user_mail: 'alice@corp.com',
          incident_sources: ['XDR Agent', 'Firewall'],
        },
        alerts: {
          data: [
            {
              alert_id: 'alert-101',
              name: 'Ransomware Behaviour Detected',
              category: 'Ransomware',
              severity: 'critical',
              source: 'XDR Agent',
              host_name: 'WKSTN-001',
              detection_timestamp: 1700000100000,
            },
            {
              alert_id: 'alert-102',
              name: 'Lateral Movement Attempt',
              category: 'Lateral Movement',
              severity: 'high',
              source: 'XDR Agent',
              host_name: 'WKSTN-002',
              detection_timestamp: 1700000200000,
            },
          ],
          total_count: 2,
          result_count: 2,
        },
      },
    }),
    update: vi.fn().mockResolvedValue(undefined),
  },
}))

vi.mock('../../../utils/formatters', () => ({
  formatEpoch: vi.fn((v: number) => `epoch:${v}`),
  relativeTime: vi.fn((v: string) => v),
}))

import XdrIncidentDetailView from '@/views/xdr/XdrIncidentDetailView.vue'

const STUBS = {
  LoadingSkeleton: true,
  EmptyState: true,
  StatusBadge: true,
  RouterLink: { template: '<a><slot /></a>' },
  Teleport: true,
}

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/cortex-xdr/incidents/:id', component: { template: '<div />' } },
  ],
})

function mountView() {
  return mount(XdrIncidentDetailView, {
    global: { plugins: [router], stubs: STUBS },
  })
}

describe('XdrIncidentDetailView', () => {
  beforeEach(async () => {
    await router.push('/cortex-xdr/incidents/test-inc-1')
    await router.isReady()
    vi.clearAllMocks()
  })

  it('renders back button with XDR Incidents label', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('XDR Incidents')
  })

  it('fetches extra data on mount using the route id', async () => {
    const { xdrIncidentsApi } = await import('../../../api/cortex')
    mountView()
    await flushPromises()
    expect(xdrIncidentsApi.getExtraData).toHaveBeenCalledWith('test-inc-1')
  })

  it('displays incident description after load', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Ransomware detected on multiple hosts')
  })

  it('displays incident severity after load', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('critical')
  })

  it('displays incident hosts', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('WKSTN-001')
    expect(wrapper.text()).toContain('WKSTN-002')
  })

  it('displays incident users', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('admin')
    expect(wrapper.text()).toContain('jdoe')
  })

  it('displays incident sources', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('XDR Agent')
    expect(wrapper.text()).toContain('Firewall')
  })

  it('shows loading state initially', () => {
    const wrapper = mountView()
    expect((wrapper.vm as any).loading).toBe(true)
  })

  it('loading is false after data is fetched', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('severityBadgeClass returns correct class for critical', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('critical')).toBe('bg-red-500/15 text-red-400')
  })

  it('severityBadgeClass returns correct class for high', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('high')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('severityBadgeClass returns correct class for medium', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('medium')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('severityBadgeClass returns correct class for low', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('low')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('severityBadgeClass returns default class for unknown', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('unknown')).toBe('bg-gray-500/15 text-gray-400')
  })

  it('severityBadgeClass handles null input', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass(null)).toBe('bg-gray-500/15 text-gray-400')
  })

  it('statusBadgeClass returns correct class for new', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('new')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('statusBadgeClass returns correct class for under_investigation', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('under_investigation')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('statusBadgeClass returns correct class for resolved_true_positive', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('resolved_true_positive')).toBe('bg-green-500/15 text-green-400')
  })

  it('statusBadgeClass returns correct class for resolved_false_positive', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('resolved_false_positive')).toBe('bg-gray-500/15 text-gray-400')
  })

  it('statusBadgeClass returns default class for unknown', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('unknown')).toBe('bg-gray-500/15 text-gray-400')
  })

  it('statusBadgeClass handles null input', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass(null)).toBe('bg-gray-500/15 text-gray-400')
  })

  it('updateStatus calls xdrIncidentsApi.update with correct id and status', async () => {
    const { xdrIncidentsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    await (wrapper.vm as any).updateStatus('under_investigation')
    await flushPromises()
    expect(xdrIncidentsApi.update).toHaveBeenCalledWith('test-inc-1', { status: 'under_investigation' })
  })

  it('updateStatus does nothing when incident is null', async () => {
    const { xdrIncidentsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.incident = null
    await vm.updateStatus('under_investigation')
    expect(xdrIncidentsApi.update).not.toHaveBeenCalled()
  })

  it('updateStatus updates local incident status after resolving', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    await vm.updateStatus('under_investigation')
    await flushPromises()
    expect(vm.incident.status).toBe('under_investigation')
  })

  it('updateStatus sets actionLoading to false after resolving', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    await vm.updateStatus('resolved_true_positive')
    await flushPromises()
    expect(vm.actionLoading).toBe(false)
  })

  it('assignUser does nothing when incident is null', async () => {
    const { xdrIncidentsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.incident = null
    await vm.assignUser()
    expect(xdrIncidentsApi.update).not.toHaveBeenCalled()
  })

  it('assignUser does nothing when prompt returns null', async () => {
    const { xdrIncidentsApi } = await import('../../../api/cortex')
    vi.spyOn(window, 'prompt').mockReturnValueOnce(null)
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    await (wrapper.vm as any).assignUser()
    expect(xdrIncidentsApi.update).not.toHaveBeenCalled()
  })

  it('assignUser calls update with email from prompt', async () => {
    const { xdrIncidentsApi } = await import('../../../api/cortex')
    vi.spyOn(window, 'prompt').mockReturnValueOnce('newuser@corp.com')
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    await (wrapper.vm as any).assignUser()
    await flushPromises()
    expect(xdrIncidentsApi.update).toHaveBeenCalledWith('test-inc-1', {
      assigned_user_mail: 'newuser@corp.com',
    })
  })

  it('assignUser updates local incident assigned_user_mail after assigning', async () => {
    vi.spyOn(window, 'prompt').mockReturnValueOnce('newuser@corp.com')
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    await vm.assignUser()
    await flushPromises()
    expect(vm.incident.assigned_user_mail).toBe('newuser@corp.com')
  })

  it('assignUser sets actionLoading to false after resolving', async () => {
    vi.spyOn(window, 'prompt').mockReturnValueOnce('user@corp.com')
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    await vm.assignUser()
    await flushPromises()
    expect(vm.actionLoading).toBe(false)
  })

  it('linked alerts tab shows alert data', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.activeTab = 'alerts'
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Ransomware Behaviour Detected')
  })

  it('linked alerts tab shows host name', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.activeTab = 'alerts'
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('WKSTN-001')
  })

  it('overview tab is active by default', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).activeTab).toBe('overview')
  })

  it('linkedAlerts count is shown in the tab', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('(2)')
  })

  it('shows "not found" state when incident is null', async () => {
    const { xdrIncidentsApi } = await import('../../../api/cortex')
    vi.mocked(xdrIncidentsApi.getExtraData).mockResolvedValueOnce({
      reply: { incident: null as unknown as import('../../../types/cortex').XdrIncident, alerts: { data: [], total_count: 0 } },
    })
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Incident not found')
  })

  it('shows Investigate button when status is new', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    // Reset incident status to 'new' to test conditional button rendering
    const vm = wrapper.vm as any
    vm.incident = { ...vm.incident, status: 'new' }
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Investigate')
  })

  it('shows Resolve (TP) button when status is not resolved', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.incident = { ...vm.incident, status: 'new' }
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Resolve (TP)')
  })

  it('shows Resolve (FP) button when status is not resolved', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.incident = { ...vm.incident, status: 'new' }
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Resolve (FP)')
  })

  it('shows Assign User button', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Assign User')
  })
})
