import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import UsersView from '../UsersView.vue'

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

const mockUsersList = vi.hoisted(() => vi.fn())

vi.mock('../../api/misc', () => ({
  usersApi: {
    list: mockUsersList,
    create: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    getApiTokenDetails: vi.fn(),
  },
}))

const FAKE_USERS = [
  { id: 'u1', fullName: 'Alice Admin', email: 'alice@acmecorp.internal', lowestRole: 'Admin', scope: 'tenant', twoFaEnabled: true, twoFaStatus: 'configured', lastLogin: '2025-06-01T10:00:00Z', apiToken: null },
  { id: 'u2', fullName: 'Bob Viewer', email: 'bob@acmecorp.internal', lowestRole: 'Viewer', scope: 'site', twoFaEnabled: false, twoFaStatus: 'not_configured', lastLogin: null, apiToken: null },
]

describe('UsersView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockUsersList.mockResolvedValue({
      data: FAKE_USERS,
      pagination: { totalItems: 2 },
    })
  })

  it('renders without error', async () => {
    const w = shallowMount(UsersView)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the Users heading', async () => {
    const w = shallowMount(UsersView)
    await flushPromises()
    expect(w.text()).toContain('Users')
  })

  it('calls usersApi.list on mount', async () => {
    shallowMount(UsersView)
    await flushPromises()
    expect(mockUsersList).toHaveBeenCalledOnce()
  })

  it('renders user full names after load', async () => {
    const w = shallowMount(UsersView)
    await flushPromises()
    expect(w.text()).toContain('Alice Admin')
    expect(w.text()).toContain('Bob Viewer')
  })

  it('renders total users count', async () => {
    const w = shallowMount(UsersView)
    await flushPromises()
    expect(w.text()).toContain('2')
  })

  it('renders Create User button', async () => {
    const w = shallowMount(UsersView)
    await flushPromises()
    expect(w.text()).toContain('Create User')
  })
})
