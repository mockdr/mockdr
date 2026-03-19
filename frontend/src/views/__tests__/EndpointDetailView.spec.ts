import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import EndpointDetailView from '@/views/EndpointDetailView.vue'

vi.mock('vue-router', () => ({
  useRoute: vi.fn(() => ({ params: { id: '123456789012345678' } })),
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

const mockAgentGet = vi.hoisted(() => vi.fn())
const mockAgentAction = vi.hoisted(() => vi.fn())
const mockAgentApplications = vi.hoisted(() => vi.fn())
const mockAgentProcesses = vi.hoisted(() => vi.fn())
const mockAgentPassphrase = vi.hoisted(() => vi.fn())
const mockThreatsList = vi.hoisted(() => vi.fn())

vi.mock('../../api/agents', () => ({
  agentsApi: {
    get: mockAgentGet,
    list: vi.fn(),
    applications: mockAgentApplications,
    processes: mockAgentProcesses,
    passphrase: mockAgentPassphrase,
    action: mockAgentAction,
  },
}))

vi.mock('../../api/threats', () => ({
  threatsApi: {
    list: mockThreatsList,
    get: vi.fn(),
    timeline: vi.fn().mockResolvedValue({ data: [] }),
    getNotes: vi.fn().mockResolvedValue({ data: [] }),
  },
}))

vi.mock('../../api/misc', () => ({
  sitesApi: { list: vi.fn().mockResolvedValue({ data: { sites: [{ id: 's1', name: 'Alpha HQ' }] } }) },
  groupsApi: { list: vi.fn().mockResolvedValue({ data: [{ id: 'g1', name: 'Workstations' }], pagination: {} }) },
}))

vi.mock('../../api/tags', () => ({
  tagsApi: {
    list: vi.fn().mockResolvedValue({ data: [{ id: 'tag-1', name: 'VIP' }, { id: 'tag-2', name: 'Critical' }] }),
  },
}))

const FAKE_AGENT = {
  id: '123456789012345678',
  uuid: 'uuid-abc',
  computerName: 'ACME-WIN-001',
  osType: 'windows',
  networkStatus: 'connected',
  infected: false,
  isActive: true,
  lastActiveDate: '2025-06-01T10:00:00Z',
  agentVersion: '23.1.0',
  ipv4: '10.0.0.5',
  externalIp: '203.0.113.10',
  domain: 'acmecorp.internal',
  siteName: 'Alpha HQ',
  siteId: 's1',
  groupId: 'g1',
  tags: { sentinelone: [{ id: 'tag-1', name: 'VIP' }] },
  activeDirectory: null,
}

const stubs = { LoadingSkeleton: true, StatusBadge: true, OsIcon: true }

describe('EndpointDetailView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockAgentGet.mockResolvedValue({ data: FAKE_AGENT })
    mockThreatsList.mockResolvedValue({ data: [] })
    mockAgentAction.mockResolvedValue({ data: { affected: 1 } })
    mockAgentApplications.mockResolvedValue({ data: [{ name: 'Chrome', version: '120.0' }] })
    mockAgentProcesses.mockResolvedValue({ data: [{ name: 'chrome.exe', pid: 1234 }] })
    mockAgentPassphrase.mockResolvedValue({ data: { passphrase: 'secret-pass-phrase' } })
  })

  it('renders without error', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('calls agentsApi.get with the route param id', async () => {
    shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    expect(mockAgentGet).toHaveBeenCalledWith('123456789012345678')
  })

  it('calls threatsApi.list with agentIds filter', async () => {
    shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    expect(mockThreatsList).toHaveBeenCalledWith(
      expect.objectContaining({ agentIds: '123456789012345678' })
    )
  })

  it('renders the agent computerName after load', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('ACME-WIN-001')
  })

  it('renders the Overview tab button', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('Overview')
  })

  it('loading is false after data loads', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).loading).toBe(false)
  })

  it('activeTab defaults to overview', () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    expect((w.vm as any).activeTab).toBe('overview')
  })

  it('TABS contains all expected tab ids', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    const tabs = (w.vm as any).TABS
    const tabIds = tabs.map((t: any) => t.id)
    expect(tabIds).toContain('overview')
    expect(tabIds).toContain('network')
    expect(tabIds).toContain('threats')
    expect(tabIds).toContain('apps')
    expect(tabIds).toContain('processes')
    expect(tabIds).toContain('actions')
  })

  it('s1Tags returns sentinelone tags from agent', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    const tags = (w.vm as any).s1Tags
    expect(tags).toHaveLength(1)
    expect(tags[0].name).toBe('VIP')
  })

  it('s1Tags returns empty array when agent has no tags', async () => {
    mockAgentGet.mockResolvedValueOnce({ data: { ...FAKE_AGENT, tags: null } })
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).s1Tags).toHaveLength(0)
  })

  it('hasAd returns false when no active directory data', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).hasAd).toBe(false)
  })

  it('hasAd returns true when active directory data present', async () => {
    mockAgentGet.mockResolvedValueOnce({
      data: { ...FAKE_AGENT, activeDirectory: { computerDistinguishedName: 'CN=ACME-WIN-001,OU=Workstations,DC=corp,DC=local' } },
    })
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).hasAd).toBe(true)
  })

  it('switchTab sets activeTab', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).switchTab('network')
    expect((w.vm as any).activeTab).toBe('network')
  })

  it('switchTab to apps calls loadApps', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).switchTab('apps')
    await flushPromises()
    expect(mockAgentApplications).toHaveBeenCalledWith('123456789012345678', { limit: 50 })
  })

  it('switchTab to processes calls loadProcesses', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).switchTab('processes')
    await flushPromises()
    expect(mockAgentProcesses).toHaveBeenCalledWith('123456789012345678', { limit: 50 })
  })

  it('loadApps skips if apps already loaded', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).switchTab('apps')
    await flushPromises()
    const firstCallCount = mockAgentApplications.mock.calls.length
    await (w.vm as any).loadApps()
    expect(mockAgentApplications.mock.calls.length).toBe(firstCallCount)
  })

  it('loadProcesses skips if processes already loaded', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).switchTab('processes')
    await flushPromises()
    const firstCallCount = mockAgentProcesses.mock.calls.length
    await (w.vm as any).loadProcesses()
    expect(mockAgentProcesses.mock.calls.length).toBe(firstCallCount)
  })

  it('doAction calls agentsApi.action and refreshes agent', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    mockAgentGet.mockClear()
    await (w.vm as any).doAction('disconnect')
    await flushPromises()
    expect(mockAgentAction).toHaveBeenCalledWith('disconnect', { filter: { ids: ['123456789012345678'] } })
    expect(mockAgentGet).toHaveBeenCalledWith('123456789012345678')
  })

  it('doAction sets actionLoading to false after completion', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).doAction('initiate-scan')
    await flushPromises()
    expect((w.vm as any).actionLoading).toBe(false)
  })

  it('showPassphrase sets passphrase from API', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).showPassphrase()
    await flushPromises()
    expect((w.vm as any).passphrase).toBe('secret-pass-phrase')
  })

  it('showPassphrase sets error message when API fails', async () => {
    mockAgentPassphrase.mockRejectedValueOnce(new Error('API error'))
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).showPassphrase()
    await flushPromises()
    expect((w.vm as any).passphrase).toBe('(failed to retrieve passphrase)')
  })

  it('switchTab to actions calls loadActionData', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).switchTab('actions')
    await flushPromises()
    expect((w.vm as any).actionDataLoaded).toBe(true)
  })

  it('loadActionData sets sites, groups, and tagDefs', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).loadActionData()
    await flushPromises()
    expect((w.vm as any).sites).toHaveLength(1)
    expect((w.vm as any).groups).toHaveLength(1)
    expect((w.vm as any).tagDefs).toHaveLength(2)
  })

  it('loadActionData skips if already loaded', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).loadActionData()
    await flushPromises()
    const { sitesApi } = await import('../../api/misc')
    vi.mocked(sitesApi.list).mockClear()
    await (w.vm as any).loadActionData()
    expect(vi.mocked(sitesApi.list)).not.toHaveBeenCalled()
  })

  it('availableTags returns tags not already assigned to agent', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).loadActionData()
    await flushPromises()
    const available = (w.vm as any).availableTags
    // tag-1 is already assigned, tag-2 should be available
    expect(available.find((t: any) => t.id === 'tag-2')).toBeDefined()
    expect(available.find((t: any) => t.id === 'tag-1')).toBeUndefined()
  })

  it('doMoveToSite does nothing when selectedSiteId is empty', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).selectedSiteId = ''
    await (w.vm as any).doMoveToSite()
    expect(mockAgentAction).not.toHaveBeenCalled()
  })

  it('doMoveToSite calls agentsApi.action with move-to-site', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).selectedSiteId = 'site-99'
    mockAgentGet.mockClear()
    await (w.vm as any).doMoveToSite()
    await flushPromises()
    expect(mockAgentAction).toHaveBeenCalledWith('move-to-site', {
      filter: { ids: ['123456789012345678'] },
      data: { targetSiteId: 'site-99' },
    })
    expect(mockAgentGet).toHaveBeenCalled()
  })

  it('doMoveToSite sets actionLoading to false after completion', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).selectedSiteId = 'site-99'
    await (w.vm as any).doMoveToSite()
    await flushPromises()
    expect((w.vm as any).actionLoading).toBe(false)
  })

  it('doMoveToGroup does nothing when selectedGroupId is empty', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).selectedGroupId = ''
    await (w.vm as any).doMoveToGroup()
    expect(mockAgentAction).not.toHaveBeenCalled()
  })

  it('doMoveToGroup calls agentsApi.action with move-to-group', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).selectedGroupId = 'grp-99'
    mockAgentGet.mockClear()
    await (w.vm as any).doMoveToGroup()
    await flushPromises()
    expect(mockAgentAction).toHaveBeenCalledWith('move-to-group', {
      filter: { ids: ['123456789012345678'] },
      data: { targetGroupId: 'grp-99' },
    })
  })

  it('addTag does nothing when selectedTagId is empty', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).selectedTagId = ''
    await (w.vm as any).addTag()
    expect(mockAgentAction).not.toHaveBeenCalled()
  })

  it('addTag calls agentsApi.action with manage-tags add', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).selectedTagId = 'tag-2'
    mockAgentGet.mockClear()
    await (w.vm as any).addTag()
    await flushPromises()
    expect(mockAgentAction).toHaveBeenCalledWith('manage-tags', {
      filter: { ids: ['123456789012345678'] },
      data: [{ tagId: 'tag-2', operation: 'add' }],
    })
  })

  it('addTag clears selectedTagId after success', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).selectedTagId = 'tag-2'
    await (w.vm as any).addTag()
    await flushPromises()
    expect((w.vm as any).selectedTagId).toBe('')
  })

  it('removeTag calls agentsApi.action with manage-tags remove', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    mockAgentGet.mockClear()
    await (w.vm as any).removeTag('tag-1')
    await flushPromises()
    expect(mockAgentAction).toHaveBeenCalledWith('manage-tags', {
      filter: { ids: ['123456789012345678'] },
      data: [{ tagId: 'tag-1', operation: 'remove' }],
    })
  })

  it('removeTag sets actionLoading to false after completion', async () => {
    const w = shallowMount(EndpointDetailView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).removeTag('tag-1')
    await flushPromises()
    expect((w.vm as any).actionLoading).toBe(false)
  })
})
