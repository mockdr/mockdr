import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import PoliciesView from '../PoliciesView.vue'

const mockSitesList = vi.hoisted(() => vi.fn())
const mockGroupsList = vi.hoisted(() => vi.fn())
const mockClientGet = vi.hoisted(() => vi.fn())

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../api/misc', () => ({
  sitesApi: { list: mockSitesList },
  groupsApi: { list: mockGroupsList },
  accountsApi: { list: vi.fn() },
  activitiesApi: { list: vi.fn() },
  exclusionsApi: { list: vi.fn() },
  blocklistApi: { list: vi.fn() },
  firewallApi: { list: vi.fn() },
  deviceControlApi: { list: vi.fn() },
  iocsApi: { list: vi.fn() },
  dvApi: { list: vi.fn() },
  usersApi: { list: vi.fn() },
}))

vi.mock('../../api/client', () => ({
  default: { get: mockClientGet, put: vi.fn() },
}))

const FAKE_SITES = [
  { id: 'site-1', name: 'Default Site' },
  { id: 'site-2', name: 'Branch Office' },
]

const FAKE_GROUPS = [{ id: 'grp-1', name: 'Windows Servers' }]

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

describe('PoliciesView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockSitesList.mockResolvedValue({ data: { sites: FAKE_SITES }, pagination: { totalItems: 2 } })
    mockGroupsList.mockResolvedValue({ data: FAKE_GROUPS })
    mockClientGet.mockResolvedValue({ data: FAKE_POLICY })
  })

  it('renders without error', async () => {
    const w = shallowMount(PoliciesView)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the Policies heading', async () => {
    const w = shallowMount(PoliciesView)
    await flushPromises()
    expect(w.text()).toContain('Policies')
  })

  it('loads sites on mount', async () => {
    shallowMount(PoliciesView)
    await flushPromises()
    expect(mockSitesList).toHaveBeenCalledOnce()
  })

  it('loads policy for the first site', async () => {
    shallowMount(PoliciesView)
    await flushPromises()
    expect(mockClientGet).toHaveBeenCalled()
  })

  it('displays policy settings after load', async () => {
    const w = shallowMount(PoliciesView)
    await flushPromises()
    expect(w.text()).toContain('Detection')
    expect(w.text()).toContain('Mitigation Mode')
  })
})
