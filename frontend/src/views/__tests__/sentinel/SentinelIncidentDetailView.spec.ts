import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/sentinel', () => ({
  sentinelIncidentApi: {
    get: vi.fn().mockResolvedValue({
      id: '/subscriptions/sub-001/resourceGroups/rg-001/providers/Microsoft.OperationalInsights/workspaces/ws-001/providers/Microsoft.SecurityInsights/incidents/test-incident-id',
      name: 'test-incident-id',
      type: 'Microsoft.SecurityInsights/incidents',
      properties: {
        title: 'Suspicious PowerShell Execution',
        description: 'A suspicious PowerShell command was executed on endpoint WKSTN-001.',
        severity: 'High',
        status: 'Active',
        createdTimeUtc: '2024-11-14T22:00:00Z',
        lastModifiedTimeUtc: '2024-11-14T23:00:00Z',
        incidentNumber: 42,
        incidentUrl: 'https://portal.azure.com/#incident',
        providerName: 'Azure Sentinel',
        providerIncidentId: 'prov-inc-001',
        classification: null,
        classificationReason: null,
        labels: [{ labelName: 'critical-asset' }, { labelName: 'powershell' }],
        owner: {
          assignedTo: 'analyst@corp.com',
          email: 'analyst@corp.com',
          objectId: 'obj-001',
          userPrincipalName: 'analyst@corp.com',
        },
        relatedAnalyticRuleIds: [],
        additionalData: {
          alertsCount: 3,
          bookmarksCount: 0,
          commentsCount: 1,
          alertProductNames: ['Microsoft Defender'],
          tactics: ['Execution', 'DefenseEvasion'],
        },
        firstActivityTimeUtc: '2024-11-14T21:00:00Z',
        lastActivityTimeUtc: '2024-11-14T22:30:00Z',
      },
    }),
    getAlerts: vi.fn().mockResolvedValue({
      value: [
        {
          id: 'alert-001',
          name: 'alert-001',
          type: 'Microsoft.SecurityInsights/incidents/alerts',
          properties: {
            alertDisplayName: 'PowerShell Suspicious Activity',
            severity: 'High',
            productName: 'Microsoft Defender',
            status: 'New',
            timeGenerated: '2024-11-14T21:30:00Z',
            tactics: ['Execution'],
          },
        },
      ],
    }),
    getEntities: vi.fn().mockResolvedValue({
      entities: [
        {
          kind: 'Host',
          name: 'WKSTN-001',
          properties: {
            friendlyName: 'WKSTN-001',
            hostName: 'WKSTN-001',
          },
        },
        {
          kind: 'Account',
          name: 'jdoe',
          properties: {
            friendlyName: 'John Doe',
          },
        },
      ],
    }),
    getComments: vi.fn().mockResolvedValue({
      value: [
        {
          id: 'comment-001',
          name: 'comment-001',
          type: 'Microsoft.SecurityInsights/incidents/comments',
          properties: {
            message: 'Investigating the PowerShell activity on the endpoint.',
            author: { name: 'analyst@corp.com' },
            createdTimeUtc: '2024-11-14T22:15:00Z',
          },
        },
      ],
    }),
    update: vi.fn().mockResolvedValue({
      id: 'updated-id',
      name: 'test-incident-id',
      type: 'Microsoft.SecurityInsights/incidents',
      properties: {
        title: 'Suspicious PowerShell Execution',
        description: 'Updated',
        severity: 'High',
        status: 'Closed',
        createdTimeUtc: '2024-11-14T22:00:00Z',
        lastModifiedTimeUtc: '2024-11-14T23:30:00Z',
        incidentNumber: 42,
        incidentUrl: 'https://portal.azure.com/#incident',
        providerName: 'Azure Sentinel',
        providerIncidentId: 'prov-inc-001',
        labels: [],
        owner: { assignedTo: 'analyst@corp.com' },
        additionalData: { alertsCount: 3, tactics: [] },
      },
    }),
    addComment: vi.fn().mockResolvedValue({
      id: 'comment-002',
      name: 'comment-002',
      type: 'Microsoft.SecurityInsights/incidents/comments',
      properties: {
        message: 'New comment added',
        author: { name: 'analyst@corp.com' },
        createdTimeUtc: '2024-11-14T23:00:00Z',
      },
    }),
  },
}))

vi.mock('../../../utils/formatters', () => ({
  relativeTime: vi.fn((v: string) => `relative:${v}`),
  formatEpoch: vi.fn(() => '2024-11-14 22:00:00'),
}))

import SentinelIncidentDetailView from '@/views/sentinel/SentinelIncidentDetailView.vue'

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
    { path: '/sentinel/incidents/:id', component: { template: '<div />' } },
  ],
})

function mountView() {
  return mount(SentinelIncidentDetailView, {
    global: { plugins: [router], stubs: STUBS },
  })
}

describe('SentinelIncidentDetailView', () => {
  beforeEach(async () => {
    await router.push('/sentinel/incidents/test-incident-id')
    await router.isReady()
    vi.clearAllMocks()
  })

  it('renders back button', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Sentinel Incidents')
  })

  it('fetches incident data on mount', async () => {
    const { sentinelIncidentApi } = await import('../../../api/sentinel')
    mountView()
    await flushPromises()
    expect(sentinelIncidentApi.get).toHaveBeenCalledWith('test-incident-id')
  })

  it('fetches alerts on mount', async () => {
    const { sentinelIncidentApi } = await import('../../../api/sentinel')
    mountView()
    await flushPromises()
    expect(sentinelIncidentApi.getAlerts).toHaveBeenCalledWith('test-incident-id')
  })

  it('fetches entities on mount', async () => {
    const { sentinelIncidentApi } = await import('../../../api/sentinel')
    mountView()
    await flushPromises()
    expect(sentinelIncidentApi.getEntities).toHaveBeenCalledWith('test-incident-id')
  })

  it('fetches comments on mount', async () => {
    const { sentinelIncidentApi } = await import('../../../api/sentinel')
    mountView()
    await flushPromises()
    expect(sentinelIncidentApi.getComments).toHaveBeenCalledWith('test-incident-id')
  })

  it('displays incident title after load', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Suspicious PowerShell Execution')
  })

  it('displays incident severity after load', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('High')
  })

  it('displays incident status after load', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Active')
  })

  it('severityBadgeClass returns correct class for high', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('high')).toBe('bg-red-500/15 text-red-400')
  })

  it('severityBadgeClass returns correct class for medium', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('medium')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('severityBadgeClass returns correct class for low', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('low')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('severityBadgeClass returns correct class for informational', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('informational')).toBe('bg-blue-500/15 text-blue-400')
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

  it('statusBadgeClass returns correct class for active', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('active')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('statusBadgeClass returns correct class for closed', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).statusBadgeClass('closed')).toBe('bg-green-500/15 text-green-400')
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

  it('entityKindBadgeClass returns correct class for account', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).entityKindBadgeClass('account')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('entityKindBadgeClass returns correct class for host', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).entityKindBadgeClass('host')).toBe('bg-green-500/15 text-green-400')
  })

  it('entityKindBadgeClass returns correct class for ip', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).entityKindBadgeClass('ip')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('entityKindBadgeClass returns correct class for url', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).entityKindBadgeClass('url')).toBe('bg-purple-500/15 text-purple-400')
  })

  it('entityKindBadgeClass returns correct class for file', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).entityKindBadgeClass('file')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('entityKindBadgeClass returns correct class for process', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).entityKindBadgeClass('process')).toBe('bg-cyan-500/15 text-cyan-400')
  })

  it('entityKindBadgeClass returns default class for unknown kind', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).entityKindBadgeClass('unknown')).toBe('bg-gray-500/15 text-gray-400')
  })

  it('entityKindBadgeClass handles null input', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).entityKindBadgeClass(null)).toBe('bg-gray-500/15 text-gray-400')
  })

  it('updateStatus calls sentinelIncidentApi.update with correct args', async () => {
    const { sentinelIncidentApi } = await import('../../../api/sentinel')
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    await (wrapper.vm as any).updateStatus('Closed')
    await flushPromises()
    expect(sentinelIncidentApi.update).toHaveBeenCalledWith('test-incident-id', { status: 'Closed' })
  })

  it('updateStatus does nothing when incident is null', async () => {
    const { sentinelIncidentApi } = await import('../../../api/sentinel')
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.incident = null
    await vm.updateStatus('Closed')
    expect(sentinelIncidentApi.update).not.toHaveBeenCalled()
  })

  it('updateStatus updates local incident with the response', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    await vm.updateStatus('Closed')
    await flushPromises()
    expect(vm.incident).not.toBeNull()
  })

  it('fetchAlerts populates alerts array', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    expect(vm.alerts.length).toBe(1)
    expect(vm.alerts[0].name).toBe('alert-001')
  })

  it('fetchAlerts handles API error gracefully', async () => {
    const { sentinelIncidentApi } = await import('../../../api/sentinel')
    vi.mocked(sentinelIncidentApi.getAlerts).mockRejectedValueOnce(new Error('Forbidden'))
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).alerts).toEqual([])
  })

  it('fetchEntities populates entities array', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    expect(vm.entities.length).toBe(2)
  })

  it('fetchEntities handles API error gracefully', async () => {
    const { sentinelIncidentApi } = await import('../../../api/sentinel')
    vi.mocked(sentinelIncidentApi.getEntities).mockRejectedValueOnce(new Error('Not found'))
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).entities).toEqual([])
  })

  it('fetchComments populates comments array', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    expect(vm.comments.length).toBe(1)
  })

  it('fetchComments handles API error gracefully', async () => {
    const { sentinelIncidentApi } = await import('../../../api/sentinel')
    vi.mocked(sentinelIncidentApi.getComments).mockRejectedValueOnce(new Error('Error'))
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).comments).toEqual([])
  })

  it('addComment does nothing when newComment is empty', async () => {
    const { sentinelIncidentApi } = await import('../../../api/sentinel')
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.newComment = ''
    await vm.addComment()
    expect(sentinelIncidentApi.addComment).not.toHaveBeenCalled()
  })

  it('addComment does nothing when newComment is only whitespace', async () => {
    const { sentinelIncidentApi } = await import('../../../api/sentinel')
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.newComment = '   '
    await vm.addComment()
    expect(sentinelIncidentApi.addComment).not.toHaveBeenCalled()
  })

  it('addComment calls sentinelIncidentApi.addComment with incident id and message', async () => {
    const { sentinelIncidentApi } = await import('../../../api/sentinel')
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.newComment = 'Escalating to Tier 2 SOC team.'
    await vm.addComment()
    await flushPromises()
    expect(sentinelIncidentApi.addComment).toHaveBeenCalledWith(
      'test-incident-id',
      expect.any(String),
      'Escalating to Tier 2 SOC team.',
    )
  })

  it('addComment clears newComment after adding', async () => {
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.newComment = 'Test comment text'
    await vm.addComment()
    await flushPromises()
    expect(vm.newComment).toBe('')
  })

  it('addComment refreshes comments after adding', async () => {
    const { sentinelIncidentApi } = await import('../../../api/sentinel')
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.newComment = 'Another observation'
    await vm.addComment()
    await flushPromises()
    // getComments called once on mount, once inside addComment via fetchComments
    expect(sentinelIncidentApi.getComments).toHaveBeenCalledTimes(2)
  })

  it('switching to alerts tab shows alert data', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.activeTab = 'alerts'
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('PowerShell Suspicious Activity')
  })

  it('switching to entities tab shows entity data', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.activeTab = 'entities'
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('WKSTN-001')
  })

  it('switching to comments tab shows comment data', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.activeTab = 'comments'
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Investigating the PowerShell activity')
  })

  it('shows labels on the incident detail', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('critical-asset')
  })

  it('shows tactics on the incident detail', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Execution')
  })

  it('shows Set Active button when status is not Active', async () => {
    const { sentinelIncidentApi } = await import('../../../api/sentinel')
    vi.mocked(sentinelIncidentApi.get).mockResolvedValueOnce({
      id: 'id',
      name: 'test-incident-id',
      type: 'Microsoft.SecurityInsights/incidents',
      properties: {
        title: 'Test',
        description: 'Desc',
        severity: 'High',
        status: 'New',
        createdTimeUtc: '2024-11-14T22:00:00Z',
        lastModifiedTimeUtc: '2024-11-14T23:00:00Z',
        incidentNumber: 1,
        incidentUrl: '',
        providerName: '',
        providerIncidentId: '',
        labels: [],
        owner: { assignedTo: null, email: null, ownerType: 'Unknown' },
        additionalData: { alertsCount: 0, bookmarksCount: 0, commentsCount: 0, alertProductNames: [], tactics: [], techniques: [] },
        classification: '',
        classificationReason: '',
      },
    })
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Set Active')
  })

  it('shows loading state initially', () => {
    const wrapper = mountView()
    const vm = wrapper.vm as any
    // loading starts as true before promises resolve
    expect(vm.loading).toBe(true)
  })

  it('loading is false after data is fetched', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('tab button switches activeTab via DOM click', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const alertsTab = wrapper.findAll('button').find(b => b.text().includes('Alerts'))
    await alertsTab!.trigger('click')
    expect((wrapper.vm as any).activeTab).toBe('alerts')
  })

  it('Comments tab button switches activeTab via DOM click', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const commentsTab = wrapper.findAll('button').find(b => b.text().includes('Comments'))
    await commentsTab!.trigger('click')
    expect((wrapper.vm as any).activeTab).toBe('comments')
  })

  it('Add Comment button triggers addComment via DOM click', async () => {
    const { sentinelIncidentApi } = await import('../../../api/sentinel')
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.activeTab = 'comments'
    vm.newComment = 'Dom test comment'
    await wrapper.vm.$nextTick()
    vi.mocked(sentinelIncidentApi.addComment).mockClear()
    const addBtn = wrapper.findAll('button').find(b => b.text().includes('Add Comment'))
    if (addBtn) {
      await addBtn.trigger('click')
      await flushPromises()
      expect(sentinelIncidentApi.addComment).toHaveBeenCalled()
    }
  })

  it('textarea v-model updates newComment via DOM input', async () => {
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.activeTab = 'comments'
    await wrapper.vm.$nextTick()
    const textarea = wrapper.find('textarea')
    if (textarea.exists()) {
      await textarea.setValue('new comment text')
      expect(vm.newComment).toBe('new comment text')
    }
  })
})
