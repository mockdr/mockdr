import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import ThreatDetailView from '../ThreatDetailView.vue'

vi.mock('vue-router', () => ({
  useRoute: vi.fn(() => ({ params: { id: '234567890123456789' } })),
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

const mockThreatGet = vi.hoisted(() => vi.fn())
const mockTimeline = vi.hoisted(() => vi.fn())
const mockGetNotes = vi.hoisted(() => vi.fn())

vi.mock('../../api/threats', () => ({
  threatsApi: {
    get: mockThreatGet,
    timeline: mockTimeline,
    getNotes: mockGetNotes,
    list: vi.fn().mockResolvedValue({ data: [] }),
    setVerdict: vi.fn().mockResolvedValue({}),
    mitigate: vi.fn().mockResolvedValue({}),
    setIncident: vi.fn().mockResolvedValue({}),
    addNote: vi.fn().mockResolvedValue({ data: { id: 'n1', text: 'note', createdAt: '2025-01-01' } }),
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
    sha256: 'abc123',
    filePath: 'C:\\Windows\\Temp\\evil.exe',
    createdAt: '2025-06-01T00:00:00Z',
    updatedAt: '2025-06-01T01:00:00Z',
  },
  agentDetectionInfo: {
    computerName: 'ACME-WIN-007',
    agentOsType: 'windows',
    agentVersion: '23.1.0',
    siteId: 's1',
    siteName: 'Alpha HQ',
  },
  agentRealtimeInfo: {
    agentComputerName: 'ACME-WIN-007',
  },
}

describe('ThreatDetailView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockThreatGet.mockResolvedValue({ data: FAKE_THREAT })
    mockTimeline.mockResolvedValue({ data: [] })
    mockGetNotes.mockResolvedValue({ data: [] })
  })

  it('renders without error', async () => {
    const w = shallowMount(ThreatDetailView)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('calls threatsApi.get with the route param id', async () => {
    shallowMount(ThreatDetailView)
    await flushPromises()
    expect(mockThreatGet).toHaveBeenCalledWith('234567890123456789')
  })

  it('calls threatsApi.timeline with the threat id', async () => {
    shallowMount(ThreatDetailView)
    await flushPromises()
    expect(mockTimeline).toHaveBeenCalledWith('234567890123456789')
  })

  it('calls threatsApi.getNotes with the threat id', async () => {
    shallowMount(ThreatDetailView)
    await flushPromises()
    expect(mockGetNotes).toHaveBeenCalledWith('234567890123456789')
  })

  it('renders threat name after load', async () => {
    const w = shallowMount(ThreatDetailView)
    await flushPromises()
    expect(w.text()).toContain('Ransomware.XYZ')
  })

  it('renders site name from agentDetectionInfo', async () => {
    const w = shallowMount(ThreatDetailView)
    await flushPromises()
    expect(w.text()).toContain('Alpha HQ')
  })
})
