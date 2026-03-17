import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import FirewallView from '../FirewallView.vue'

const mockFirewallList = vi.hoisted(() => vi.fn())
const mockSitesList = vi.hoisted(() => vi.fn())

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../api/misc', () => ({
  firewallApi: {
    list: mockFirewallList,
    create: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
  sitesApi: {
    list: mockSitesList,
  },
}))

const FAKE_RULES = [
  {
    id: 'fw1', name: 'Allow HTTPS', description: 'Allow outbound HTTPS', action: 'Allow',
    direction: 'outbound', status: 'Enabled', protocol: 'TCP', order: 1,
    osTypes: ['windows'], editable: true,
    remoteHosts: [{ type: 'any', values: [] }],
    remotePort: { type: 'ports', values: ['443'] },
  },
  {
    id: 'fw2', name: 'Block Telnet', description: null, action: 'Block',
    direction: 'inbound', status: 'Enabled', protocol: 'TCP', order: 2,
    osTypes: ['linux'], editable: true,
    remoteHosts: [{ type: 'any', values: [] }],
    remotePort: { type: 'ports', values: ['23'] },
  },
]

describe('FirewallView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFirewallList.mockResolvedValue({
      data: FAKE_RULES,
      pagination: { totalItems: 2 },
    })
    mockSitesList.mockResolvedValue({
      data: { sites: [{ id: 's1', name: 'Alpha HQ' }] },
    })
  })

  it('renders without error', async () => {
    const w = shallowMount(FirewallView)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the Firewall Rules heading', async () => {
    const w = shallowMount(FirewallView)
    await flushPromises()
    expect(w.text()).toContain('Firewall Rules')
  })

  it('calls firewallApi.list and sitesApi.list on mount', async () => {
    shallowMount(FirewallView)
    await flushPromises()
    expect(mockFirewallList).toHaveBeenCalledOnce()
    expect(mockSitesList).toHaveBeenCalledOnce()
  })

  it('renders firewall rule names after load', async () => {
    const w = shallowMount(FirewallView)
    await flushPromises()
    expect(w.text()).toContain('Allow HTTPS')
    expect(w.text()).toContain('Block Telnet')
  })

  it('renders total rules count', async () => {
    const w = shallowMount(FirewallView)
    await flushPromises()
    expect(w.text()).toContain('2')
  })

  it('renders New Rule button', async () => {
    const w = shallowMount(FirewallView)
    await flushPromises()
    expect(w.text()).toContain('New Rule')
  })

  it('renders port values for rules', async () => {
    const w = shallowMount(FirewallView)
    await flushPromises()
    expect(w.text()).toContain('443')
    expect(w.text()).toContain('23')
  })
})
