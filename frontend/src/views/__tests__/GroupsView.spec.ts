import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import GroupsView from '../GroupsView.vue'

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

const mockGroupsList = vi.hoisted(() => vi.fn())
const mockSitesList = vi.hoisted(() => vi.fn())

vi.mock('../../api/misc', () => ({
  groupsApi: {
    list: mockGroupsList,
    create: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
  sitesApi: { list: mockSitesList },
}))

const FAKE_GROUPS = [
  { id: 'g1', name: 'Windows Servers', siteId: 's1', type: 'static', totalAgents: 10, createdAt: '2025-01-01T00:00:00Z', isDefault: false },
  { id: 'g2', name: 'Linux Workstations', siteId: 's1', type: 'pinned', totalAgents: 5, createdAt: '2025-01-02T00:00:00Z', isDefault: true },
]

describe('GroupsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGroupsList.mockResolvedValue({
      data: FAKE_GROUPS,
      pagination: { totalItems: 2 },
    })
    mockSitesList.mockResolvedValue({
      data: { sites: [{ id: 's1', name: 'Alpha HQ' }] },
    })
  })

  it('renders without error', async () => {
    const w = shallowMount(GroupsView)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the Groups heading', async () => {
    const w = shallowMount(GroupsView)
    await flushPromises()
    expect(w.text()).toContain('Groups')
  })

  it('calls groupsApi.list and sitesApi.list on mount', async () => {
    shallowMount(GroupsView)
    await flushPromises()
    expect(mockGroupsList).toHaveBeenCalledOnce()
    expect(mockSitesList).toHaveBeenCalledOnce()
  })

  it('renders group names after load', async () => {
    const w = shallowMount(GroupsView)
    await flushPromises()
    expect(w.text()).toContain('Windows Servers')
    expect(w.text()).toContain('Linux Workstations')
  })

  it('renders total groups count', async () => {
    const w = shallowMount(GroupsView)
    await flushPromises()
    expect(w.text()).toContain('2')
  })
})
