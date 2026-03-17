import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import EndpointDetailView from '../EndpointDetailView.vue'

vi.mock('vue-router', () => ({
  useRoute: vi.fn(() => ({ params: { id: '123456789012345678' } })),
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

const mockAgentGet = vi.hoisted(() => vi.fn())
const mockThreatsList = vi.hoisted(() => vi.fn())

vi.mock('../../api/agents', () => ({
  agentsApi: {
    get: mockAgentGet,
    list: vi.fn(),
    applications: vi.fn().mockResolvedValue({ data: [] }),
    processes: vi.fn().mockResolvedValue({ data: [] }),
    passphrase: vi.fn().mockResolvedValue({ data: { passphrase: 'test' } }),
    action: vi.fn().mockResolvedValue({ data: { affected: 1 } }),
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
  sitesApi: { list: vi.fn().mockResolvedValue({ data: { sites: [] } }) },
  groupsApi: { list: vi.fn().mockResolvedValue({ data: [], pagination: {} }) },
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
}

describe('EndpointDetailView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockAgentGet.mockResolvedValue({ data: FAKE_AGENT })
    mockThreatsList.mockResolvedValue({ data: [] })
  })

  it('renders without error', async () => {
    const w = shallowMount(EndpointDetailView)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('calls agentsApi.get with the route param id', async () => {
    shallowMount(EndpointDetailView)
    await flushPromises()
    expect(mockAgentGet).toHaveBeenCalledWith('123456789012345678')
  })

  it('calls threatsApi.list with agentIds filter', async () => {
    shallowMount(EndpointDetailView)
    await flushPromises()
    expect(mockThreatsList).toHaveBeenCalledWith(
      expect.objectContaining({ agentIds: '123456789012345678' })
    )
  })

  it('renders the agent computerName after load', async () => {
    const w = shallowMount(EndpointDetailView)
    await flushPromises()
    expect(w.text()).toContain('ACME-WIN-001')
  })

  it('renders the Overview tab button', async () => {
    const w = shallowMount(EndpointDetailView)
    await flushPromises()
    expect(w.text()).toContain('Overview')
  })
})
