import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import SitesView from '../SitesView.vue'

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

const mockSitesList = vi.hoisted(() => vi.fn())

vi.mock('../../api/misc', () => ({
  sitesApi: { list: mockSitesList, create: vi.fn(), update: vi.fn(), delete: vi.fn() },
}))

const FAKE_SITES = [
  { id: 's1', name: 'Alpha HQ', accountId: 'acc1', siteType: 'Paid', totalLicenses: 50 },
  { id: 's2', name: 'Beta Office', accountId: 'acc1', siteType: 'Paid', totalLicenses: 25 },
]

describe('SitesView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockSitesList.mockResolvedValue({
      data: { sites: FAKE_SITES, allSites: {} },
      pagination: { totalItems: 2 },
    })
  })

  it('renders without error', async () => {
    const w = shallowMount(SitesView)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the Sites heading', async () => {
    const w = shallowMount(SitesView)
    await flushPromises()
    expect(w.text()).toContain('Sites')
  })

  it('calls sitesApi.list on mount', async () => {
    shallowMount(SitesView)
    await flushPromises()
    expect(mockSitesList).toHaveBeenCalledOnce()
  })

  it('renders site names after load', async () => {
    const w = shallowMount(SitesView)
    await flushPromises()
    expect(w.text()).toContain('Alpha HQ')
    expect(w.text()).toContain('Beta Office')
  })

  it('renders total sites count', async () => {
    const w = shallowMount(SitesView)
    await flushPromises()
    expect(w.text()).toContain('2')
  })
})
