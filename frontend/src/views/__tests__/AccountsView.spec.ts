import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import AccountsView from '../AccountsView.vue'

const mockList = vi.hoisted(() => vi.fn())

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../api/misc', () => ({
  accountsApi: { list: mockList, create: vi.fn(), update: vi.fn() },
  sitesApi: { list: vi.fn() },
  groupsApi: { list: vi.fn() },
  activitiesApi: { list: vi.fn() },
  exclusionsApi: { list: vi.fn() },
  blocklistApi: { list: vi.fn() },
  firewallApi: { list: vi.fn() },
  deviceControlApi: { list: vi.fn() },
  iocsApi: { list: vi.fn() },
  dvApi: { list: vi.fn() },
  usersApi: { list: vi.fn() },
}))

const FAKE_ACCOUNTS = [
  {
    id: 'acc-1',
    name: 'Acme Corp',
    state: 'active',
    accountType: 'Paid',
    numberOfSites: 3,
    activeAgents: 42,
    numberOfAgents: 50,
    numberOfUsers: 5,
    createdAt: '2025-01-15T10:00:00Z',
  },
  {
    id: 'acc-2',
    name: 'Beta Inc',
    state: 'expired',
    accountType: 'Trial',
    numberOfSites: 1,
    activeAgents: 0,
    numberOfAgents: 2,
    numberOfUsers: 1,
    createdAt: '2025-03-01T08:00:00Z',
  },
]

describe('AccountsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockList.mockResolvedValue({
      data: FAKE_ACCOUNTS,
      pagination: { totalItems: 2 },
    })
  })

  it('renders without error', async () => {
    const w = shallowMount(AccountsView)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the Accounts heading', async () => {
    const w = shallowMount(AccountsView)
    await flushPromises()
    expect(w.text()).toContain('Accounts')
  })

  it('calls accountsApi.list on mount', async () => {
    shallowMount(AccountsView)
    await flushPromises()
    expect(mockList).toHaveBeenCalledOnce()
  })

  it('renders account names after load', async () => {
    const w = shallowMount(AccountsView)
    await flushPromises()
    expect(w.text()).toContain('Acme Corp')
    expect(w.text()).toContain('Beta Inc')
  })

  it('displays total accounts count', async () => {
    const w = shallowMount(AccountsView)
    await flushPromises()
    expect(w.text()).toContain('2')
  })

  it('displays account type', async () => {
    const w = shallowMount(AccountsView)
    await flushPromises()
    expect(w.text()).toContain('Paid')
    expect(w.text()).toContain('Trial')
  })
})
