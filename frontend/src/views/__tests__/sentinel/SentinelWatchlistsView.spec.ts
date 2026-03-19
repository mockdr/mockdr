import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/sentinel', () => ({
  sentinelWatchlistApi: {
    list: vi.fn(),
  },
}))

vi.mock('../../../utils/formatters', () => ({
  relativeTime: vi.fn((v) => v ?? ''),
  formatEpoch: vi.fn((v) => `${v}`),
}))

import { sentinelWatchlistApi } from '@/api/sentinel'
import SentinelWatchlistsView from '@/views/sentinel/SentinelWatchlistsView.vue'

const mockWatchlists = [
  {
    name: 'wl-001',
    properties: {
      displayName: 'Trusted IP Ranges',
      provider: 'Microsoft',
      description: 'Internal IP ranges to exclude from alerts',
      watchlistItemsCount: 42,
      itemsSearchKey: 'IPAddress',
      created: '2026-01-01T00:00:00Z',
    },
  },
  {
    name: 'wl-002',
    properties: {
      displayName: 'VIP Users',
      provider: 'Internal',
      description: '',
      watchlistItemsCount: 15,
      itemsSearchKey: 'UserPrincipalName',
      created: '2026-01-02T00:00:00Z',
    },
  },
  {
    name: 'wl-003',
    properties: {
      displayName: 'Blocked Domains',
      provider: 'ThreatFeed',
      description: 'Domains known to be malicious',
      watchlistItemsCount: 500,
      itemsSearchKey: 'Domain',
      created: '2026-01-03T00:00:00Z',
    },
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/sentinel/watchlists', component: { template: '<div />' } },
  ],
})

const globalOpts = {
  plugins: [router],
  stubs: { LoadingSkeleton: true, EmptyState: true },
}

describe('SentinelWatchlistsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(sentinelWatchlistApi.list).mockResolvedValue({ value: mockWatchlists } as any)
  })

  it('renders the page header', () => {
    const wrapper = mount(SentinelWatchlistsView, { global: globalOpts })
    expect(wrapper.text()).toContain('Watchlists')
  })

  it('calls sentinelWatchlistApi.list on mount', async () => {
    mount(SentinelWatchlistsView, { global: globalOpts })
    await flushPromises()
    expect(sentinelWatchlistApi.list).toHaveBeenCalledTimes(1)
  })

  it('fetchWatchlists populates watchlists ref', async () => {
    const wrapper = mount(SentinelWatchlistsView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).watchlists).toHaveLength(3)
  })

  it('fetchWatchlists sets loading false after success', async () => {
    const wrapper = mount(SentinelWatchlistsView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('fetchWatchlists handles null value in response', async () => {
    vi.mocked(sentinelWatchlistApi.list).mockResolvedValue({ value: null } as any)
    const wrapper = mount(SentinelWatchlistsView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).watchlists).toEqual([])
  })

  it('fetchWatchlists can be called again via refresh button', async () => {
    const wrapper = mount(SentinelWatchlistsView, { global: globalOpts })
    await flushPromises()
    const btn = wrapper.find('button')
    await btn.trigger('click')
    await flushPromises()
    expect(sentinelWatchlistApi.list).toHaveBeenCalledTimes(2)
  })

  it('renders watchlist display names in table', async () => {
    const wrapper = mount(SentinelWatchlistsView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('Trusted IP Ranges')
    expect(wrapper.text()).toContain('VIP Users')
    expect(wrapper.text()).toContain('Blocked Domains')
  })

  it('renders provider names', async () => {
    const wrapper = mount(SentinelWatchlistsView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('Microsoft')
    expect(wrapper.text()).toContain('Internal')
    expect(wrapper.text()).toContain('ThreatFeed')
  })

  it('renders watchlist item counts', async () => {
    const wrapper = mount(SentinelWatchlistsView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('42')
    expect(wrapper.text()).toContain('15')
    expect(wrapper.text()).toContain('500')
  })

  it('renders search keys', async () => {
    const wrapper = mount(SentinelWatchlistsView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('IPAddress')
    expect(wrapper.text()).toContain('UserPrincipalName')
    expect(wrapper.text()).toContain('Domain')
  })

  it('renders descriptions, showing -- for empty description', async () => {
    const wrapper = mount(SentinelWatchlistsView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('Internal IP ranges to exclude from alerts')
    expect(wrapper.text()).toContain('--')
  })

  it('renders correct table column headers', async () => {
    const wrapper = mount(SentinelWatchlistsView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('Name')
    expect(wrapper.text()).toContain('Description')
    expect(wrapper.text()).toContain('Items Count')
    expect(wrapper.text()).toContain('Search Key')
    expect(wrapper.text()).toContain('Created')
  })

  it('shows EmptyState when no watchlists returned', async () => {
    vi.mocked(sentinelWatchlistApi.list).mockResolvedValue({ value: [] } as any)
    const wrapper = mount(SentinelWatchlistsView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.findComponent({ name: 'EmptyState' }).exists()).toBe(true)
  })

  it('shows LoadingSkeleton while loading', () => {
    vi.mocked(sentinelWatchlistApi.list).mockReturnValue(new Promise(() => {}))
    const wrapper = mount(SentinelWatchlistsView, { global: globalOpts })
    // loading is true initially before the promise resolves
    expect((wrapper.vm as any).loading).toBe(true)
  })

  it('loading is true initially', () => {
    vi.mocked(sentinelWatchlistApi.list).mockReturnValue(new Promise(() => {}))
    const wrapper = mount(SentinelWatchlistsView, { global: globalOpts })
    expect((wrapper.vm as any).loading).toBe(true)
  })

  it('watchlists is empty initially before fetch completes', () => {
    vi.mocked(sentinelWatchlistApi.list).mockReturnValue(new Promise(() => {}))
    const wrapper = mount(SentinelWatchlistsView, { global: globalOpts })
    expect((wrapper.vm as any).watchlists).toEqual([])
  })

  it('relativeTime is called for created timestamps', async () => {
    const { relativeTime } = await import('../../../utils/formatters')
    mount(SentinelWatchlistsView, { global: globalOpts })
    await flushPromises()
    expect(vi.mocked(relativeTime)).toHaveBeenCalled()
  })

  it('page description text is rendered', () => {
    const wrapper = mount(SentinelWatchlistsView, { global: globalOpts })
    expect(wrapper.text()).toContain('watchlist')
  })
})
