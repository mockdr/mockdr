import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import TagsView from '../TagsView.vue'

const mockTagsList = vi.hoisted(() => vi.fn())
const mockSitesList = vi.hoisted(() => vi.fn())
const mockGroupsList = vi.hoisted(() => vi.fn())
const mockAccountsList = vi.hoisted(() => vi.fn())

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../api/tags', () => ({
  tagsApi: {
    list: mockTagsList,
    create: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
}))

vi.mock('../../api/misc', () => ({
  sitesApi: { list: mockSitesList },
  groupsApi: { list: mockGroupsList },
  accountsApi: { list: mockAccountsList },
  activitiesApi: { list: vi.fn() },
  exclusionsApi: { list: vi.fn() },
  blocklistApi: { list: vi.fn() },
  firewallApi: { list: vi.fn() },
  deviceControlApi: { list: vi.fn() },
  iocsApi: { list: vi.fn() },
  dvApi: { list: vi.fn() },
  usersApi: { list: vi.fn() },
}))

const FAKE_TAGS = [
  {
    id: 'tag-1',
    key: 'Environment',
    value: 'Production',
    scopeLevel: 'global',
    scopePath: '/',
    totalEndpoints: 40,
    endpointsInCurrentScope: 40,
    description: 'Production endpoints',
    createdAt: '2025-04-01T10:00:00Z',
  },
  {
    id: 'tag-2',
    key: 'Virtual',
    value: 'Virtual',
    scopeLevel: 'site',
    scopePath: '/ Default Site',
    totalEndpoints: 12,
    endpointsInCurrentScope: 12,
    description: '',
    createdAt: '2025-04-02T10:00:00Z',
  },
]

describe('TagsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockTagsList.mockResolvedValue({ data: FAKE_TAGS, pagination: { totalItems: 2 } })
    mockSitesList.mockResolvedValue({ data: { sites: [] } })
    mockGroupsList.mockResolvedValue({ data: [] })
    mockAccountsList.mockResolvedValue({ data: [] })
  })

  it('renders without error', async () => {
    const w = shallowMount(TagsView)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the Endpoint Tags heading', async () => {
    const w = shallowMount(TagsView)
    await flushPromises()
    expect(w.text()).toContain('Endpoint Tags')
  })

  it('calls tagsApi.list on mount', async () => {
    shallowMount(TagsView)
    await flushPromises()
    expect(mockTagsList).toHaveBeenCalledOnce()
  })

  it('renders tag keys after load', async () => {
    const w = shallowMount(TagsView)
    await flushPromises()
    expect(w.text()).toContain('Environment')
    expect(w.text()).toContain('Virtual')
  })

  it('displays total tag count', async () => {
    const w = shallowMount(TagsView)
    await flushPromises()
    expect(w.text()).toContain('2 tag definitions')
  })

  it('renders scope badges', async () => {
    const w = shallowMount(TagsView)
    await flushPromises()
    expect(w.text()).toContain('global')
    expect(w.text()).toContain('site')
  })
})
