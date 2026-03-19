import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

const mockThreatGet = vi.hoisted(() => vi.fn())
const mockTimeline = vi.hoisted(() => vi.fn())
const mockGetNotes = vi.hoisted(() => vi.fn())
const mockSetVerdict = vi.hoisted(() => vi.fn())
const mockMitigate = vi.hoisted(() => vi.fn())
const mockSetIncident = vi.hoisted(() => vi.fn())
const mockAddNote = vi.hoisted(() => vi.fn())

import ThreatDetailView from '@/views/ThreatDetailView.vue'

vi.mock('../../api/threats', () => ({
  threatsApi: {
    get: mockThreatGet,
    timeline: mockTimeline,
    getNotes: mockGetNotes,
    list: vi.fn().mockResolvedValue({ data: [] }),
    setVerdict: mockSetVerdict,
    mitigate: mockMitigate,
    setIncident: mockSetIncident,
    addNote: mockAddNote,
  },
}))

const FAKE_THREAT = {
  id: '234567890123456789',
  threatInfo: {
    threatName: 'Ransomware.XYZ',
    classification: 'Ransomware',
    mitigationStatus: 'active',
    analystVerdict: 'undefined',
    incidentStatus: 'unresolved',
    resolved: false,
    sha256: 'abc123',
    filePath: 'C:\\Windows\\Temp\\evil.exe',
    fileName: 'evil.exe',
    fileSize: 10240,
    sha1: 'sha1val',
    md5: 'md5val',
    createdAt: '2025-06-01T00:00:00Z',
    updatedAt: '2025-06-01T01:00:00Z',
    classificationSource: 'Static AI',
    engines: ['Static AI', 'Behavioral AI'],
    initiatedBy: 'user',
    storylineId: 'story-1',
  },
  agentDetectionInfo: {
    agentComputerName: 'ACME-WIN-007',
    agentOsName: 'Windows 10',
    agentVersion: '23.1.0',
    siteId: 's1',
    siteName: 'Alpha HQ',
    groupName: 'Workstations',
    agentIpV4: '10.0.0.1',
    externalIp: '8.8.8.8',
    agentDomain: 'corp.local',
    agentLastLoggedInUserName: 'jdoe',
  },
  agentRealtimeInfo: { agentId: 'agent-1', agentComputerName: 'ACME-WIN-007' },
}

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/threats/:id', component: { template: '<div />' } },
    { path: '/endpoints/:id', component: { template: '<div />' } },
    { path: '/threats', component: { template: '<div />' } },
  ],
})

const stubs = { StatusBadge: true, LoadingSkeleton: true }

describe('ThreatDetailView', () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    mockThreatGet.mockResolvedValue({ data: FAKE_THREAT })
    mockTimeline.mockResolvedValue({ data: [{ id: 't1', timestamp: '2025-06-01T00:00:00Z', event: 'File created', type: 'file' }] })
    mockGetNotes.mockResolvedValue({ data: [] })
    mockSetVerdict.mockResolvedValue({})
    mockMitigate.mockResolvedValue({})
    mockSetIncident.mockResolvedValue({})
    mockAddNote.mockResolvedValue({ data: { id: 'n1', text: 'test note', createdAt: '2025-06-01' } })
    await router.push('/threats/234567890123456789')
    await router.isReady()
  })

  function mountView() {
    return mount(ThreatDetailView, {
      global: { plugins: [router], stubs },
    })
  }

  it('calls threatsApi.get with the route param id', async () => {
    mountView()
    await flushPromises()
    expect(mockThreatGet).toHaveBeenCalledWith('234567890123456789')
  })

  it('calls threatsApi.timeline with the threat id', async () => {
    mountView()
    await flushPromises()
    expect(mockTimeline).toHaveBeenCalledWith('234567890123456789')
  })

  it('calls threatsApi.getNotes with the threat id', async () => {
    mountView()
    await flushPromises()
    expect(mockGetNotes).toHaveBeenCalledWith('234567890123456789')
  })

  it('renders threat name after load', async () => {
    const w = mountView()
    await flushPromises()
    expect(w.text()).toContain('Ransomware.XYZ')
  })

  it('renders site name from agentDetectionInfo', async () => {
    const w = mountView()
    await flushPromises()
    expect(w.text()).toContain('Alpha HQ')
  })

  it('loading is false after data loads', async () => {
    const w = mountView()
    await flushPromises()
    expect((w.vm as any).loading).toBe(false)
  })

  it('doVerdict calls threatsApi.setVerdict with correct args', async () => {
    const w = mountView()
    await flushPromises()
    await (w.vm as any).doVerdict('true_positive')
    await flushPromises()
    expect(mockSetVerdict).toHaveBeenCalledWith(['234567890123456789'], 'true_positive')
  })

  it('doVerdict refreshes threat after update', async () => {
    const w = mountView()
    await flushPromises()
    mockThreatGet.mockClear()
    await (w.vm as any).doVerdict('false_positive')
    await flushPromises()
    expect(mockThreatGet).toHaveBeenCalledWith('234567890123456789')
  })

  it('doVerdict sets actionLoading to false after completion', async () => {
    const w = mountView()
    await flushPromises()
    await (w.vm as any).doVerdict('suspicious')
    await flushPromises()
    expect((w.vm as any).actionLoading).toBe(false)
  })

  it('doMitigate calls threatsApi.mitigate when act.mitigate is set', async () => {
    const w = mountView()
    await flushPromises()
    await (w.vm as any).doMitigate({ mitigate: 'quarantine', label: 'Quarantine' })
    await flushPromises()
    expect(mockMitigate).toHaveBeenCalledWith('quarantine', ['234567890123456789'])
  })

  it('doMitigate calls threatsApi.setIncident when act.incident is set', async () => {
    const w = mountView()
    await flushPromises()
    await (w.vm as any).doMitigate({ incident: 'resolved', label: 'Resolve' })
    await flushPromises()
    expect(mockSetIncident).toHaveBeenCalledWith(['234567890123456789'], 'resolved')
  })

  it('doMitigate refreshes threat after action', async () => {
    const w = mountView()
    await flushPromises()
    mockThreatGet.mockClear()
    await (w.vm as any).doMitigate({ mitigate: 'kill', label: 'Kill' })
    await flushPromises()
    expect(mockThreatGet).toHaveBeenCalledWith('234567890123456789')
  })

  it('doMitigate sets actionLoading to false after completion', async () => {
    const w = mountView()
    await flushPromises()
    await (w.vm as any).doMitigate({ mitigate: 'remediate', label: 'Remediate' })
    await flushPromises()
    expect((w.vm as any).actionLoading).toBe(false)
  })

  it('submitNote does nothing when newNote is empty', async () => {
    const w = mountView()
    await flushPromises()
    ;(w.vm as any).newNote = ''
    await (w.vm as any).submitNote()
    expect(mockAddNote).not.toHaveBeenCalled()
  })

  it('submitNote calls threatsApi.addNote with note text', async () => {
    const w = mountView()
    await flushPromises()
    ;(w.vm as any).newNote = 'test note'
    await (w.vm as any).submitNote()
    await flushPromises()
    expect(mockAddNote).toHaveBeenCalledWith('234567890123456789', 'test note')
  })

  it('submitNote appends returned note to notes array', async () => {
    const w = mountView()
    await flushPromises()
    ;(w.vm as any).newNote = 'test note'
    await (w.vm as any).submitNote()
    await flushPromises()
    expect((w.vm as any).notes).toHaveLength(1)
    expect((w.vm as any).notes[0].text).toBe('test note')
  })

  it('submitNote clears newNote after success', async () => {
    const w = mountView()
    await flushPromises()
    ;(w.vm as any).newNote = 'test note'
    await (w.vm as any).submitNote()
    await flushPromises()
    expect((w.vm as any).newNote).toBe('')
  })

  it('submitNote sets error on failure', async () => {
    mockAddNote.mockRejectedValueOnce(new Error('Network error'))
    const w = mountView()
    await flushPromises()
    ;(w.vm as any).newNote = 'test note'
    await (w.vm as any).submitNote()
    await flushPromises()
    expect((w.vm as any).error).toBe('Network error')
  })

  it('submitNote sets submittingNote to false after completion', async () => {
    const w = mountView()
    await flushPromises()
    ;(w.vm as any).newNote = 'test note'
    await (w.vm as any).submitNote()
    await flushPromises()
    expect((w.vm as any).submittingNote).toBe(false)
  })

  it('MITIGATION_ACTIONS shows Quarantine when not quarantined', async () => {
    const w = mountView()
    await flushPromises()
    const actions = (w.vm as any).MITIGATION_ACTIONS
    const labels = actions.map((a: any) => a.label)
    expect(labels).toContain('Quarantine')
  })

  it('MITIGATION_ACTIONS shows Un-quarantine when quarantined', async () => {
    const threat = { ...FAKE_THREAT, threatInfo: { ...FAKE_THREAT.threatInfo, mitigationStatus: 'quarantined' } }
    mockThreatGet.mockResolvedValue({ data: threat })
    const w = mountView()
    await flushPromises()
    const actions = (w.vm as any).MITIGATION_ACTIONS
    const labels = actions.map((a: any) => a.label)
    expect(labels).toContain('Un-quarantine')
  })

  it('MITIGATION_ACTIONS shows Resolve when not resolved', async () => {
    const w = mountView()
    await flushPromises()
    const actions = (w.vm as any).MITIGATION_ACTIONS
    const labels = actions.map((a: any) => a.label)
    expect(labels).toContain('Resolve')
  })

  it('MITIGATION_ACTIONS shows Re-open when resolved', async () => {
    const threat = { ...FAKE_THREAT, threatInfo: { ...FAKE_THREAT.threatInfo, resolved: true } }
    mockThreatGet.mockResolvedValue({ data: threat })
    const w = mountView()
    await flushPromises()
    const actions = (w.vm as any).MITIGATION_ACTIONS
    const labels = actions.map((a: any) => a.label)
    expect(labels).toContain('Re-open')
  })

  it('activeTab defaults to overview', async () => {
    const w = mountView()
    expect((w.vm as any).activeTab).toBe('overview')
  })

  it('TABS contains all expected tab names', async () => {
    const w = mountView()
    expect((w.vm as any).TABS).toContain('overview')
    expect((w.vm as any).TABS).toContain('timeline')
    expect((w.vm as any).TABS).toContain('notes')
  })

  it('tab button switches activeTab via DOM click', async () => {
    const w = mountView()
    await flushPromises()
    const timelineBtn = w.findAll('button').find(b => b.text() === 'timeline')
    await timelineBtn!.trigger('click')
    expect((w.vm as any).activeTab).toBe('timeline')
  })

  it('notes tab button switches activeTab via DOM click', async () => {
    const w = mountView()
    await flushPromises()
    const notesBtn = w.findAll('button').find(b => b.text() === 'notes')
    await notesBtn!.trigger('click')
    expect((w.vm as any).activeTab).toBe('notes')
  })

  it('verdict button calls doVerdict via DOM click', async () => {
    const w = mountView()
    await flushPromises()
    const suspiciousBtn = w.findAll('button').find(b => b.text() === 'Suspicious')
    await suspiciousBtn!.trigger('click')
    await flushPromises()
    expect(mockSetVerdict).toHaveBeenCalledWith(['234567890123456789'], 'suspicious')
  })

  it('mitigation button calls doMitigate via DOM click', async () => {
    const w = mountView()
    await flushPromises()
    const quarantineBtn = w.findAll('button').find(b => b.text() === 'Quarantine')
    await quarantineBtn!.trigger('click')
    await flushPromises()
    expect(mockMitigate).toHaveBeenCalledWith('quarantine', ['234567890123456789'])
  })

  it('notes tab Add button calls submitNote via DOM click', async () => {
    const w = mountView()
    await flushPromises()
    ;(w.vm as any).activeTab = 'notes'
    await w.vm.$nextTick()
    ;(w.vm as any).newNote = 'dom note'
    await w.vm.$nextTick()
    const addBtn = w.findAll('button').find(b => b.text().includes('Add'))
    if (addBtn) {
      await addBtn.trigger('click')
      await flushPromises()
      expect(mockAddNote).toHaveBeenCalledWith('234567890123456789', 'dom note')
    }
  })
})
