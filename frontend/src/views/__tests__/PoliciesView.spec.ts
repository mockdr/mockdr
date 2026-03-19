import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import PoliciesView from '@/views/PoliciesView.vue'

const mockSitesList = vi.hoisted(() => vi.fn())
const mockGroupsList = vi.hoisted(() => vi.fn())
const mockClientGet = vi.hoisted(() => vi.fn())
const mockClientPut = vi.hoisted(() => vi.fn())

vi.mock('../../api/misc', () => ({
  sitesApi: { list: mockSitesList },
  groupsApi: { list: mockGroupsList },
}))

vi.mock('../../api/client', () => ({
  default: { get: mockClientGet, put: mockClientPut },
}))

const FAKE_SITES = [
  { id: 'site-1', name: 'Default Site' },
  { id: 'site-2', name: 'Branch Office' },
]

const FAKE_GROUPS = [
  { id: 'grp-1', name: 'Windows Servers' },
  { id: 'grp-2', name: 'Linux Servers' },
]

const FAKE_POLICY = {
  mitigationMode: 'protect',
  mitigationModeSuspicious: 'detect',
  autoMitigate: true,
  scanNewAgents: true,
  scanOnWritten: false,
  monitorOnWrite: true,
  monitorOnExecute: true,
  blockOnWrite: false,
  blockOnExecute: true,
  engines: { preExecution: true, onAccess: true, behavioralAI: false },
}

const stubs = { LoadingSkeleton: true }

describe('PoliciesView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockSitesList.mockResolvedValue({ data: { sites: FAKE_SITES }, pagination: { totalItems: 2 } })
    mockGroupsList.mockResolvedValue({ data: FAKE_GROUPS })
    mockClientGet.mockResolvedValue({ data: FAKE_POLICY })
    mockClientPut.mockResolvedValue({ data: FAKE_POLICY })
  })

  it('renders the Policies heading', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('Policies')
  })

  it('loads sites on mount', async () => {
    mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    expect(mockSitesList).toHaveBeenCalledOnce()
  })

  it('loads policy for the first site after mount', async () => {
    mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    expect(mockClientGet).toHaveBeenCalled()
  })

  it('displays policy settings after load', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('Detection')
    expect(w.text()).toContain('Mitigation Mode')
  })

  it('displays policy values', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('protect')
  })

  it('boolLabel returns Enabled for true', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).boolLabel(true)).toBe('Enabled')
  })

  it('boolLabel returns Disabled for false', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).boolLabel(false)).toBe('Disabled')
  })

  it('boolClass returns success class for true', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).boolClass(true)).toContain('success')
  })

  it('boolClass returns muted class for false', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).boolClass(false)).toContain('muted')
  })

  it('modeClass returns success for protect', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).modeClass('protect')).toContain('success')
  })

  it('modeClass returns yellow for detect', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).modeClass('detect')).toContain('yellow')
  })

  it('modeClass returns muted for none', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).modeClass('none')).toContain('muted')
  })

  it('openEdit copies policy to draft', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openEdit()
    expect((w.vm as any).draft).not.toBeNull()
    expect((w.vm as any).draft.mitigationMode).toBe('protect')
  })

  it('openEdit does nothing when policy is null', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).policy = null
    ;(w.vm as any).openEdit()
    expect((w.vm as any).draft).toBeNull()
  })

  it('cancelEdit clears draft', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openEdit()
    ;(w.vm as any).cancelEdit()
    expect((w.vm as any).draft).toBeNull()
  })

  it('savePolicy calls client.put with draft data', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openEdit()
    ;(w.vm as any).draft.mitigationMode = 'detect'
    await (w.vm as any).savePolicy()
    await flushPromises()
    expect(mockClientPut).toHaveBeenCalledWith('/policies', expect.objectContaining({ mitigationMode: 'detect' }), expect.any(Object))
  })

  it('savePolicy does nothing when draft is null', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).savePolicy()
    expect(mockClientPut).not.toHaveBeenCalled()
  })

  it('savePolicy does nothing when no params (no site or group selected)', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openEdit()
    ;(w.vm as any).selectedSite = null
    ;(w.vm as any).selectedGroup = null
    await (w.vm as any).savePolicy()
    expect(mockClientPut).not.toHaveBeenCalled()
  })

  it('savePolicy clears draft after saving', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openEdit()
    await (w.vm as any).savePolicy()
    await flushPromises()
    expect((w.vm as any).draft).toBeNull()
  })

  it('onScopeChange reloads policy', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    mockClientGet.mockClear()
    await (w.vm as any).onScopeChange()
    await flushPromises()
    expect(mockClientGet).toHaveBeenCalled()
  })

  it('onScopeChange loads groups when switching to group scope', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    mockGroupsList.mockClear()
    ;(w.vm as any).scopeType = 'group'
    await (w.vm as any).onScopeChange()
    await flushPromises()
    expect(mockGroupsList).toHaveBeenCalled()
  })

  it('onSiteChange reloads policy for new site', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).selectedSite = FAKE_SITES[1]
    mockClientGet.mockClear()
    await (w.vm as any).onSiteChange()
    await flushPromises()
    expect(mockClientGet).toHaveBeenCalled()
  })

  it('onSiteChange loads groups when scope is group', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).scopeType = 'group'
    mockGroupsList.mockClear()
    await (w.vm as any).onSiteChange()
    await flushPromises()
    expect(mockGroupsList).toHaveBeenCalled()
  })

  it('onGroupChange reloads policy', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).scopeType = 'group'
    ;(w.vm as any).selectedGroup = FAKE_GROUPS[1]
    mockClientGet.mockClear()
    await (w.vm as any).onGroupChange()
    await flushPromises()
    expect(mockClientGet).toHaveBeenCalled()
  })

  it('loadPolicy loads policy with siteId param for site scope', async () => {
    mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    expect(mockClientGet).toHaveBeenCalledWith('/policies', expect.objectContaining({ params: { siteId: 'site-1' } }))
  })

  it('loadPolicy loads policy with groupId param for group scope', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).scopeType = 'group'
    ;(w.vm as any).selectedGroup = FAKE_GROUPS[0]
    mockClientGet.mockClear()
    await (w.vm as any).loadPolicy()
    await flushPromises()
    expect(mockClientGet).toHaveBeenCalledWith('/policies', expect.objectContaining({ params: { groupId: 'grp-1' } }))
  })

  it('loadGroupsForSite clears groups when no site selected', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).selectedSite = null
    await (w.vm as any).loadGroupsForSite()
    expect((w.vm as any).groups).toEqual([])
    expect((w.vm as any).selectedGroup).toBeNull()
  })

  it('loadPolicy clears policy when no params available', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).selectedSite = null
    ;(w.vm as any).selectedGroup = null
    await (w.vm as any).loadPolicy()
    expect((w.vm as any).policy).toBeNull()
  })

  it('shows no-groups message when scope is group with no groups', async () => {
    mockGroupsList.mockResolvedValue({ data: [] })
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).scopeType = 'group'
    ;(w.vm as any).groups = []
    ;(w.vm as any).policy = null
    ;(w.vm as any).draft = null
    await w.vm.$nextTick()
    expect(w.text()).toContain('No groups found for this site')
  })

  it('Site button triggers scopeType change and onScopeChange via DOM click', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).scopeType = 'group'
    await w.vm.$nextTick()
    mockClientGet.mockClear()
    const siteBtn = w.findAll('button').find(b => b.text() === 'Site')
    await siteBtn!.trigger('click')
    await flushPromises()
    expect((w.vm as any).scopeType).toBe('site')
    expect(mockClientGet).toHaveBeenCalled()
  })

  it('Group button triggers scopeType change and onScopeChange via DOM click', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    mockClientGet.mockClear()
    const groupBtn = w.findAll('button').find(b => b.text() === 'Group')
    await groupBtn!.trigger('click')
    await flushPromises()
    expect((w.vm as any).scopeType).toBe('group')
    expect(mockClientGet).toHaveBeenCalled()
  })

  it('Edit Policy button triggers openEdit via DOM click', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    const editBtn = w.findAll('button').find(b => b.text().includes('Edit Policy'))
    await editBtn!.trigger('click')
    expect((w.vm as any).draft).not.toBeNull()
  })

  it('Cancel button triggers cancelEdit via DOM click', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openEdit()
    await w.vm.$nextTick()
    const cancelBtn = w.findAll('button').find(b => b.text().includes('Cancel'))
    await cancelBtn!.trigger('click')
    expect((w.vm as any).draft).toBeNull()
  })

  it('Save button triggers savePolicy via DOM click', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openEdit()
    await w.vm.$nextTick()
    const saveBtn = w.findAll('button').find(b => b.text().includes('Save'))
    await saveBtn!.trigger('click')
    await flushPromises()
    expect(mockClientPut).toHaveBeenCalled()
  })

  it('boolean toggle button in Detection section toggles field via DOM click', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openEdit()
    await w.vm.$nextTick()
    const initialAutoMitigate = (w.vm as any).draft.autoMitigate
    const toggleBtn = w.findAll('button').find(b => b.text() === 'Enabled' || b.text() === 'Disabled')
    await toggleBtn!.trigger('click')
    // value should have been toggled
    expect((w.vm as any).draft.autoMitigate).toBe(!initialAutoMitigate)
  })

  it('engine toggle button toggles engine state via DOM click', async () => {
    const w = mount(PoliciesView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openEdit()
    await w.vm.$nextTick()
    const initialPreExec = (w.vm as any).draft.engines.preExecution
    const engineBtn = w.findAll('button').find(b => b.text() === 'On' || b.text() === 'Off')
    await engineBtn!.trigger('click')
    expect((w.vm as any).draft.engines.preExecution).toBe(!initialPreExec)
  })
})
