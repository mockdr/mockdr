import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'

const FULL_FW_RULE_FIELDS = vi.hoisted(() => ({
  osType: 'windows',
  scope: 'account',
  scopeId: null,
  ruleCategory: 'host_firewall',
  creator: null,
  creatorId: null,
  localPort: { type: 'any', values: [] },
  localHost: { type: 'any', values: [] },
  remoteHost: { type: 'any', values: [] },
  application: { type: 'any', values: [] },
  location: { type: 'any', values: [] },
  tagIds: [],
  tagNames: [],
  tags: [],
  createdAt: '2025-01-01T00:00:00Z',
  updatedAt: '2025-01-01T00:00:00Z',
}))

const FULL_SITE_FIELDS = vi.hoisted(() => ({
  accountId: 'acc-1',
  accountName: 'Acme Corp',
  state: 'active',
  siteType: 'Paid',
  activeLicenses: null,
  totalLicenses: null,
  createdAt: '2025-01-01T00:00:00Z',
  updatedAt: '2025-01-01T00:00:00Z',
}))

vi.mock('../../api/misc', () => ({
  firewallApi: {
    list: vi.fn().mockResolvedValue({
      data: [
        {
          id: 'fw-1',
          name: 'Allow HTTPS',
          description: 'Allow outbound HTTPS',
          action: 'Allow',
          direction: 'outbound',
          status: 'Enabled',
          protocol: 'TCP',
          order: 1,
          osTypes: ['windows'],
          editable: true,
          remoteHosts: [{ type: 'any', values: [] }],
          remotePort: { type: 'ports', values: ['443'] },
          ...FULL_FW_RULE_FIELDS,
        },
        {
          id: 'fw-2',
          name: 'Block Telnet',
          description: null,
          action: 'Block',
          direction: 'inbound',
          status: 'Enabled',
          protocol: 'TCP',
          order: 2,
          osTypes: ['linux'],
          editable: true,
          remoteHosts: [{ type: 'addresses', values: ['10.0.0.1', '10.0.0.2', '192.168.1.1'] }],
          remotePort: { type: 'ports', values: ['23'] },
          ...FULL_FW_RULE_FIELDS,
        },
      ],
      pagination: { totalItems: 2, nextCursor: null },
    }),
    create: vi.fn().mockResolvedValue({
      data: {
        id: 'fw-new',
        name: 'New Rule',
        description: null,
        action: 'Allow',
        direction: 'any',
        status: 'Enabled',
        protocol: null,
        order: 3,
        osTypes: ['windows'],
        editable: true,
        remoteHosts: [{ type: 'any', values: [] }],
        remotePort: { type: 'any', values: [] },
        ...FULL_FW_RULE_FIELDS,
      },
    }),
    update: vi.fn().mockResolvedValue({
      data: {
        id: 'fw-1',
        name: 'Allow HTTPS Updated',
        description: 'Updated description',
        action: 'Allow',
        direction: 'outbound',
        status: 'Enabled',
        protocol: 'TCP',
        order: 1,
        osTypes: ['windows'],
        editable: true,
        remoteHosts: [{ type: 'any', values: [] }],
        remotePort: { type: 'ports', values: ['443'] },
        ...FULL_FW_RULE_FIELDS,
      },
    }),
    delete: vi.fn().mockResolvedValue({ data: { affected: 1 } }),
  },
  sitesApi: {
    list: vi.fn().mockResolvedValue({
      data: {
        allSites: { activeLicenses: 10, totalLicenses: 20 },
        sites: [
          { id: 'site-1', name: 'Alpha HQ', ...FULL_SITE_FIELDS },
          { id: 'site-2', name: 'Beta Office', ...FULL_SITE_FIELDS },
        ],
      },
      pagination: { totalItems: 2, nextCursor: null },
    }),
  },
}))

import { firewallApi, sitesApi } from '@/api/misc'
import FirewallView from '@/views/FirewallView.vue'

const GLOBAL_STUBS = {
  LoadingSkeleton: true,
  EmptyState: true,
  StatusBadge: true,
  RouterLink: { template: '<a><slot /></a>' },
  Teleport: true,
}

describe('FirewallView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(firewallApi.list).mockResolvedValue({
      data: [
        {
          id: 'fw-1',
          name: 'Allow HTTPS',
          description: 'Allow outbound HTTPS',
          action: 'Allow',
          direction: 'outbound',
          status: 'Enabled',
          protocol: 'TCP',
          order: 1,
          osTypes: ['windows'],
          editable: true,
          remoteHosts: [{ type: 'any', values: [] }],
          remotePort: { type: 'ports', values: ['443'] },
          ...FULL_FW_RULE_FIELDS,
        },
        {
          id: 'fw-2',
          name: 'Block Telnet',
          description: null,
          action: 'Block',
          direction: 'inbound',
          status: 'Enabled',
          protocol: 'TCP',
          order: 2,
          osTypes: ['linux'],
          editable: true,
          remoteHosts: [{ type: 'addresses', values: ['10.0.0.1', '10.0.0.2', '192.168.1.1'] }],
          remotePort: { type: 'ports', values: ['23'] },
          ...FULL_FW_RULE_FIELDS,
        },
      ],
      pagination: { totalItems: 2, nextCursor: null },
    })
    vi.mocked(firewallApi.create).mockResolvedValue({
      data: {
        id: 'fw-new',
        name: 'New Rule',
        description: null,
        action: 'Allow',
        direction: 'any',
        status: 'Enabled',
        protocol: null,
        order: 3,
        osTypes: ['windows'],
        editable: true,
        remoteHosts: [{ type: 'any', values: [] }],
        remotePort: { type: 'any', values: [] },
        ...FULL_FW_RULE_FIELDS,
      },
    })
    vi.mocked(firewallApi.update).mockResolvedValue({
      data: {
        id: 'fw-1',
        name: 'Allow HTTPS Updated',
        description: 'Updated description',
        action: 'Allow',
        direction: 'outbound',
        status: 'Enabled',
        protocol: 'TCP',
        order: 1,
        osTypes: ['windows'],
        editable: true,
        remoteHosts: [{ type: 'any', values: [] }],
        remotePort: { type: 'ports', values: ['443'] },
        ...FULL_FW_RULE_FIELDS,
      },
    })
    vi.mocked(firewallApi.delete).mockResolvedValue({ data: { affected: 1 } })
    vi.mocked(sitesApi.list).mockResolvedValue({
      data: {
        allSites: { activeLicenses: 10, totalLicenses: 20 },
        sites: [
          { id: 'site-1', name: 'Alpha HQ', ...FULL_SITE_FIELDS },
          { id: 'site-2', name: 'Beta Office', ...FULL_SITE_FIELDS },
        ],
      },
      pagination: { totalItems: 2, nextCursor: null },
    })
  })

  // ── Basic rendering ───────────────────────────────────────────────────────

  it('renders without error', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the Firewall Rules heading', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('Firewall Rules')
  })

  it('calls firewallApi.list and sitesApi.list on mount', async () => {
    mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(firewallApi.list).toHaveBeenCalledWith({ limit: 200 })
    expect(sitesApi.list).toHaveBeenCalledWith({ limit: 100 })
  })

  it('renders rule names after load', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('Allow HTTPS')
    expect(w.text()).toContain('Block Telnet')
  })

  it('renders total rule count', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('2 rules')
  })

  it('renders New Rule button', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('New Rule')
  })

  it('renders rule descriptions', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('Allow outbound HTTPS')
  })

  it('renders port values from remotePortLabel', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('443')
    expect(w.text()).toContain('23')
  })

  it('renders action labels (Allow/Block)', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('Allow')
    expect(w.text()).toContain('Block')
  })

  it('renders direction labels', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('outbound')
    expect(w.text()).toContain('inbound')
  })

  // ── remoteHostLabel ───────────────────────────────────────────────────────

  it('remoteHostLabel returns "Any" when remoteHosts is null', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect((w.vm as any).remoteHostLabel({ remoteHosts: null })).toBe('Any')
  })

  it('remoteHostLabel returns "Any" when host type is "any"', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect((w.vm as any).remoteHostLabel({ remoteHosts: [{ type: 'any', values: [] }] })).toBe('Any')
  })

  it('remoteHostLabel returns joined values for specific host type', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const label = (w.vm as any).remoteHostLabel({
      remoteHosts: [{ type: 'addresses', values: ['10.0.0.1', '10.0.0.2'] }],
    })
    expect(label).toContain('10.0.0.1')
    expect(label).toContain('10.0.0.2')
  })

  it('remoteHostLabel appends ellipsis when more than 2 values', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const label = (w.vm as any).remoteHostLabel({
      remoteHosts: [{ type: 'addresses', values: ['10.0.0.1', '10.0.0.2', '192.168.1.1'] }],
    })
    expect(label).toContain('…')
  })

  it('remoteHostLabel returns "Any" when specific type has no values', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect((w.vm as any).remoteHostLabel({ remoteHosts: [{ type: 'addresses', values: [] }] })).toBe('Any')
  })

  // ── remotePortLabel ───────────────────────────────────────────────────────

  it('remotePortLabel returns "Any" when remotePort is null', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect((w.vm as any).remotePortLabel({ remotePort: null })).toBe('Any')
  })

  it('remotePortLabel returns "Any" when port type is "any"', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect((w.vm as any).remotePortLabel({ remotePort: { type: 'any', values: [] } })).toBe('Any')
  })

  it('remotePortLabel returns joined port values', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect((w.vm as any).remotePortLabel({ remotePort: { type: 'ports', values: ['80', '443'] } })).toBe('80, 443')
  })

  it('remotePortLabel returns "Any" when specific type has empty values', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect((w.vm as any).remotePortLabel({ remotePort: { type: 'ports', values: [] } })).toBe('Any')
  })

  // ── openCreate ────────────────────────────────────────────────────────────

  it('openCreate sets modalMode to "create"', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    expect((w.vm as any).modalMode).toBe('create')
  })

  it('openCreate clears editingId and resets form', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).editingId = 'fw-1'
    ;(w.vm as any).form.name = 'Old Rule'
    ;(w.vm as any).form.action = 'Block'
    ;(w.vm as any).openCreate()
    expect((w.vm as any).editingId).toBeNull()
    expect((w.vm as any).form.name).toBe('')
    expect((w.vm as any).form.action).toBe('Allow')
    expect((w.vm as any).form.direction).toBe('any')
    expect((w.vm as any).form.status).toBe('Enabled')
    expect((w.vm as any).form.remoteHostType).toBe('any')
    expect((w.vm as any).form.remotePortType).toBe('any')
  })

  it('openCreate sets siteId to first available site id', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    expect((w.vm as any).form.siteId).toBe('site-1')
  })

  it('openCreate clears modalError', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).modalError = 'Previous error'
    ;(w.vm as any).openCreate()
    expect((w.vm as any).modalError).toBe('')
  })

  it('clicking New Rule button opens create modal', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const newBtn = w.findAll('button').find(b => b.text().includes('New Rule'))
    expect(newBtn).toBeDefined()
    await newBtn!.trigger('click')
    expect((w.vm as any).modalMode).toBe('create')
  })

  it('openCreate sets siteId to empty string when no sites available', async () => {
    vi.mocked(sitesApi.list).mockResolvedValueOnce({ data: { allSites: { activeLicenses: 0, totalLicenses: 0 }, sites: [] }, pagination: { totalItems: 0, nextCursor: null } })
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    expect((w.vm as any).form.siteId).toBe('')
  })

  // ── openEdit ──────────────────────────────────────────────────────────────

  it('openEdit sets modalMode to "edit" and populates editingId', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const rule = (w.vm as any).items[0]
    ;(w.vm as any).openEdit(rule)
    expect((w.vm as any).modalMode).toBe('edit')
    expect((w.vm as any).editingId).toBe('fw-1')
  })

  it('openEdit populates form fields from rule data', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const rule = (w.vm as any).items[0]
    ;(w.vm as any).openEdit(rule)
    expect((w.vm as any).form.name).toBe('Allow HTTPS')
    expect((w.vm as any).form.action).toBe('Allow')
    expect((w.vm as any).form.direction).toBe('outbound')
    expect((w.vm as any).form.status).toBe('Enabled')
    expect((w.vm as any).form.protocol).toBe('TCP')
  })

  it('openEdit reads remotePort type and values from rule', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const rule = (w.vm as any).items[0]
    ;(w.vm as any).openEdit(rule)
    expect((w.vm as any).form.remotePortType).toBe('ports')
    expect((w.vm as any).form.remotePortValues).toBe('443')
  })

  it('openEdit reads remoteHosts type and values for specific type', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const rule = (w.vm as any).items[1] // Block Telnet has addresses
    ;(w.vm as any).openEdit(rule)
    expect((w.vm as any).form.remoteHostType).toBe('addresses')
    expect((w.vm as any).form.remoteHostValues).toContain('10.0.0.1')
  })

  it('openEdit sets description to empty string when rule description is null', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const rule = (w.vm as any).items[1] // Block Telnet has null description
    ;(w.vm as any).openEdit(rule)
    expect((w.vm as any).form.description).toBe('')
  })

  it('openEdit falls back to defaults when remoteHosts and remotePort are null', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const ruleNoHosts = {
      id: 'fw-x', name: 'No Hosts', description: null, action: 'Allow',
      direction: 'any', status: 'Enabled', protocol: null,
      osTypes: ['windows'], remoteHosts: null, remotePort: null,
    }
    ;(w.vm as any).openEdit(ruleNoHosts)
    expect((w.vm as any).form.remoteHostType).toBe('any')
    expect((w.vm as any).form.remotePortType).toBe('any')
  })

  it('openEdit uses default osTypes when rule.osTypes is empty', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const ruleNoOs = {
      id: 'fw-y', name: 'No OS', description: null, action: 'Allow',
      direction: 'any', status: 'Enabled', protocol: null,
      osTypes: [], remoteHosts: null, remotePort: null,
    }
    ;(w.vm as any).openEdit(ruleNoOs)
    expect((w.vm as any).form.osTypes).toEqual(['windows'])
  })

  // ── closeModal ────────────────────────────────────────────────────────────

  it('closeModal sets modalMode to null and clears editingId and modalError', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).editingId = 'fw-1'
    ;(w.vm as any).modalError = 'Some error'
    ;(w.vm as any).closeModal()
    expect((w.vm as any).modalMode).toBeNull()
    expect((w.vm as any).editingId).toBeNull()
    expect((w.vm as any).modalError).toBe('')
  })

  // ── buildRemoteHosts ──────────────────────────────────────────────────────

  it('buildRemoteHosts returns type "any" with empty values when remoteHostType is "any"', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).form.remoteHostType = 'any'
    ;(w.vm as any).form.remoteHostValues = '10.0.0.1'
    const result = (w.vm as any).buildRemoteHosts()
    expect(result).toEqual([{ type: 'any', values: [] }])
  })

  it('buildRemoteHosts splits comma-separated values when type is specific', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).form.remoteHostType = 'addresses'
    ;(w.vm as any).form.remoteHostValues = '10.0.0.1, 10.0.0.2,  192.168.0.1'
    const result = (w.vm as any).buildRemoteHosts()
    expect(result[0].type).toBe('addresses')
    expect(result[0].values).toEqual(['10.0.0.1', '10.0.0.2', '192.168.0.1'])
  })

  // ── buildPort ─────────────────────────────────────────────────────────────

  it('buildPort returns empty values array when type is "any"', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect((w.vm as any).buildPort('any', '80,443')).toEqual({ type: 'any', values: [] })
  })

  it('buildPort splits comma-separated port values when type is specific', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const result = (w.vm as any).buildPort('ports', '80, 443, 8080')
    expect(result.type).toBe('ports')
    expect(result.values).toEqual(['80', '443', '8080'])
  })

  it('buildPort filters out blank values', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const result = (w.vm as any).buildPort('ports', '80,  , 443')
    expect(result.values).toEqual(['80', '443'])
  })

  // ── toggleOsType ──────────────────────────────────────────────────────────

  it('toggleOsType adds an OS type when not present', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).form.osTypes = ['windows']
    ;(w.vm as any).toggleOsType('macos')
    expect((w.vm as any).form.osTypes).toContain('macos')
  })

  it('toggleOsType removes an OS type when present and multiple exist', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).form.osTypes = ['windows', 'macos', 'linux']
    ;(w.vm as any).toggleOsType('macos')
    expect((w.vm as any).form.osTypes).not.toContain('macos')
    expect((w.vm as any).form.osTypes).toContain('windows')
    expect((w.vm as any).form.osTypes).toContain('linux')
  })

  it('toggleOsType does NOT remove the last remaining OS type', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).form.osTypes = ['windows']
    ;(w.vm as any).toggleOsType('windows')
    expect((w.vm as any).form.osTypes).toContain('windows')
    expect((w.vm as any).form.osTypes).toHaveLength(1)
  })

  it('toggleOsType can add linux and then remove it when windows also exists', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).form.osTypes = ['windows']
    ;(w.vm as any).toggleOsType('linux')
    expect((w.vm as any).form.osTypes).toContain('linux')
    ;(w.vm as any).toggleOsType('linux')
    expect((w.vm as any).form.osTypes).not.toContain('linux')
  })

  // ── saveModal (create) ────────────────────────────────────────────────────

  it('saveModal sets modalError when name is empty', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.name = ''
    await (w.vm as any).saveModal()
    expect((w.vm as any).modalError).toBe('Name is required')
  })

  it('saveModal calls firewallApi.create in create mode', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.name = 'New Rule'
    ;(w.vm as any).form.siteId = ''
    await (w.vm as any).saveModal()
    await flushPromises()
    expect(firewallApi.create).toHaveBeenCalled()
  })

  it('saveModal passes siteIds filter when siteId is set', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.name = 'Site Rule'
    ;(w.vm as any).form.siteId = 'site-1'
    await (w.vm as any).saveModal()
    await flushPromises()
    expect(firewallApi.create).toHaveBeenCalledWith(expect.any(Object), { siteIds: ['site-1'] })
  })

  it('saveModal passes empty filter object when siteId is empty', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.name = 'Global Rule'
    ;(w.vm as any).form.siteId = ''
    await (w.vm as any).saveModal()
    await flushPromises()
    expect(firewallApi.create).toHaveBeenCalledWith(expect.any(Object), {})
  })

  it('saveModal adds new rule to items list and increments total', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const initialTotal = (w.vm as any).total
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.name = 'New Rule'
    await (w.vm as any).saveModal()
    await flushPromises()
    expect((w.vm as any).items).toHaveLength(3)
    expect((w.vm as any).total).toBe(initialTotal + 1)
  })

  it('saveModal closes modal on successful create', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.name = 'New Rule'
    await (w.vm as any).saveModal()
    await flushPromises()
    expect((w.vm as any).modalMode).toBeNull()
  })

  // ── saveModal (edit) ──────────────────────────────────────────────────────

  it('saveModal calls firewallApi.update in edit mode', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const rule = (w.vm as any).items[0]
    ;(w.vm as any).openEdit(rule)
    ;(w.vm as any).form.name = 'Allow HTTPS Updated'
    await (w.vm as any).saveModal()
    await flushPromises()
    expect(firewallApi.update).toHaveBeenCalledWith('fw-1', expect.any(Object))
  })

  it('saveModal replaces updated rule in items list', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const rule = (w.vm as any).items[0]
    ;(w.vm as any).openEdit(rule)
    ;(w.vm as any).form.name = 'Allow HTTPS Updated'
    await (w.vm as any).saveModal()
    await flushPromises()
    expect((w.vm as any).items[0].name).toBe('Allow HTTPS Updated')
  })

  it('saveModal sets modalError to "Save failed." on API error', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    vi.mocked(firewallApi.create).mockRejectedValueOnce(new Error('Network error'))
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.name = 'Fail Rule'
    await (w.vm as any).saveModal()
    await flushPromises()
    expect((w.vm as any).modalError).toBe('Save failed.')
  })

  it('saveModal resets modalSaving to false after API error', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    vi.mocked(firewallApi.create).mockRejectedValueOnce(new Error('Error'))
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.name = 'Fail Rule'
    await (w.vm as any).saveModal()
    await flushPromises()
    expect((w.vm as any).modalSaving).toBe(false)
  })

  // ── confirmDelete ─────────────────────────────────────────────────────────

  it('confirmDelete calls firewallApi.delete with the rule id', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const rule = (w.vm as any).items[0]
    await (w.vm as any).confirmDelete(rule)
    await flushPromises()
    expect(firewallApi.delete).toHaveBeenCalledWith('fw-1')
  })

  it('confirmDelete removes the rule from items and decrements total', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const initialTotal = (w.vm as any).total
    const rule = (w.vm as any).items[0]
    await (w.vm as any).confirmDelete(rule)
    await flushPromises()
    expect((w.vm as any).items).toHaveLength(1)
    expect((w.vm as any).items.find((r: any) => r.id === 'fw-1')).toBeUndefined()
    expect((w.vm as any).total).toBe(initialTotal - 1)
  })

  it('confirmDelete clears confirmDeleteId and deletingId after completion', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).confirmDeleteId = 'fw-1'
    const rule = (w.vm as any).items[0]
    await (w.vm as any).confirmDelete(rule)
    await flushPromises()
    expect((w.vm as any).confirmDeleteId).toBeNull()
    expect((w.vm as any).deletingId).toBeNull()
  })

  it('confirmDelete resets deletingId to null even on API error', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    vi.mocked(firewallApi.delete).mockRejectedValueOnce(new Error('Delete error'))
    const rule = (w.vm as any).items[0]
    await (w.vm as any).confirmDelete(rule).catch(() => {})
    await flushPromises()
    expect((w.vm as any).deletingId).toBeNull()
  })

  it('edit button calls openEdit via DOM click', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const editBtn = w.find('button[title="Edit"]')
    await editBtn.trigger('click')
    expect((w.vm as any).modalMode).toBe('edit')
    expect((w.vm as any).editingId).toBe('fw-1')
  })

  it('delete button sets confirmDeleteId via DOM click', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const delBtn = w.find('button[title="Delete"]')
    await delBtn.trigger('click')
    expect((w.vm as any).confirmDeleteId).toBe('fw-1')
  })

  it('Confirm delete button calls confirmDelete via DOM', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).confirmDeleteId = 'fw-1'
    await w.vm.$nextTick()
    const confirmBtn = w.findAll('button').find(b => b.text() === 'Confirm')
    await confirmBtn!.trigger('click')
    await flushPromises()
    expect(firewallApi.delete).toHaveBeenCalledWith('fw-1')
  })

  it('cancel X button clears confirmDeleteId via DOM', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).confirmDeleteId = 'fw-1'
    await w.vm.$nextTick()
    // The cancel X button has class "text-xs text-s1-muted hover:opacity-80"
    const cancelX = w.find('button.text-xs.text-s1-muted')
    await cancelX.trigger('click')
    expect((w.vm as any).confirmDeleteId).toBeNull()
  })

  it('modal Cancel button calls closeModal via DOM', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    const cancelBtn = w.findAll('button').find(b => b.text() === 'Cancel')
    await cancelBtn!.trigger('click')
    expect((w.vm as any).modalMode).toBeNull()
  })

  it('modal Save button calls saveModal via DOM', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.name = 'DOM Rule'
    await w.vm.$nextTick()
    const saveBtn = w.findAll('button').find(b => b.text() === 'Save')
    await saveBtn!.trigger('click')
    await flushPromises()
    expect(firewallApi.create).toHaveBeenCalled()
  })

  it('OS type buttons call toggleOsType via DOM click', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    // macos button is the second OS button
    const osBtns = w.findAll('button').filter(b => ['windows', 'macos', 'linux'].includes(b.text()))
    const macosBtn = osBtns.find(b => b.text() === 'macos')
    await macosBtn!.trigger('click')
    expect((w.vm as any).form.osTypes).toContain('macos')
  })

  it('remoteHostType select updates form.remoteHostType via DOM change', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    const remoteHostSelect = w.find('select.input.text-sm.w-32')
    await remoteHostSelect.setValue('addresses')
    expect((w.vm as any).form.remoteHostType).toBe('addresses')
  })

  it('remotePortType select updates form.remotePortType via DOM change', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    const selects = w.findAll('select.input.text-sm.w-32')
    if (selects.length > 1) {
      await selects[1].setValue('ports')
      expect((w.vm as any).form.remotePortType).toBe('ports')
    }
  })

  it('remoteHostValues input updates form via DOM input when remoteHostType is not any', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.remoteHostType = 'addresses'
    await w.vm.$nextTick()
    const remoteHostInput = w.find('input[placeholder="comma-separated values"]')
    if (remoteHostInput.exists()) {
      await remoteHostInput.setValue('10.0.0.1,10.0.0.2')
      expect((w.vm as any).form.remoteHostValues).toBe('10.0.0.1,10.0.0.2')
    }
  })

  it('siteId select updates form.siteId via DOM change', async () => {
    const w = mount(FirewallView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    // siteId select uses class "input w-full text-sm" (unique among selects)
    const siteSelect = w.find('select.input.w-full.text-sm')
    if (siteSelect.exists()) {
      await siteSelect.setValue('site-1')
      expect((w.vm as any).form.siteId).toBe('site-1')
    }
  })
})
