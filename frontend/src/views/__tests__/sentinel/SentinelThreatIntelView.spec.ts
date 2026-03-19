import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/sentinel', () => ({
  sentinelThreatIntelApi: {
    list: vi.fn(),
  },
}))

vi.mock('../../../utils/formatters', () => ({
  relativeTime: vi.fn((v) => v ?? ''),
  formatEpoch: vi.fn((v) => `${v}`),
}))

import { sentinelThreatIntelApi } from '@/api/sentinel'
import SentinelThreatIntelView from '@/views/sentinel/SentinelThreatIntelView.vue'

const mockIndicators = [
  {
    name: 'ti-001',
    properties: {
      displayName: 'Malicious IP',
      pattern: "[ipv4-addr:value = '10.0.0.1']",
      patternType: 'ipv4-addr',
      source: 'ThreatFeed-A',
      confidence: 90,
      labels: ['malware', 'c2', 'ransomware', 'apt'],
      validFrom: '2026-01-01T00:00:00Z',
    },
  },
  {
    name: 'ti-002',
    properties: {
      displayName: 'Phishing URL',
      pattern: "[url:value = 'http://evil.example.com']",
      patternType: 'url',
      source: 'ThreatFeed-B',
      confidence: 75,
      labels: ['phishing'],
      validFrom: '2026-01-02T00:00:00Z',
    },
  },
  {
    name: 'ti-003',
    properties: {
      displayName: 'Bad Domain',
      pattern: "[domain-name:value = 'malicious.example.com']",
      patternType: 'domain-name',
      source: 'InternalTI',
      confidence: 55,
      labels: [],
      validFrom: '2026-01-03T00:00:00Z',
    },
  },
  {
    name: 'ti-004',
    properties: {
      displayName: 'IPv6 Threat',
      pattern: "[ipv6-addr:value = '::1']",
      patternType: 'ipv6-addr',
      source: null,
      confidence: 30,
      labels: null,
      validFrom: '2026-01-04T00:00:00Z',
    },
  },
  {
    name: 'ti-005',
    properties: {
      displayName: 'Malicious File Hash',
      pattern: "[file:hashes.'SHA-256' = 'abc123']",
      patternType: 'file',
      source: 'OSINT',
      confidence: 45,
      labels: ['malware'],
      validFrom: '2026-01-05T00:00:00Z',
    },
  },
  {
    name: 'ti-006',
    properties: {
      displayName: 'Spear Phishing Email',
      pattern: "[email-addr:value = 'attacker@evil.com']",
      patternType: 'email-addr',
      source: 'OSINT',
      confidence: 60,
      labels: ['phishing'],
      validFrom: '2026-01-06T00:00:00Z',
    },
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/sentinel/threat-intel', component: { template: '<div />' } },
  ],
})

const globalOpts = {
  plugins: [router],
  stubs: { LoadingSkeleton: true, EmptyState: true },
}

describe('SentinelThreatIntelView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(sentinelThreatIntelApi.list).mockResolvedValue({ value: mockIndicators } as any)
  })

  it('renders the page header', () => {
    const wrapper = mount(SentinelThreatIntelView, { global: globalOpts })
    expect(wrapper.text()).toContain('Threat Intelligence')
  })

  it('calls sentinelThreatIntelApi.list on mount', async () => {
    mount(SentinelThreatIntelView, { global: globalOpts })
    await flushPromises()
    expect(sentinelThreatIntelApi.list).toHaveBeenCalledTimes(1)
  })

  it('fetchIndicators populates indicators ref', async () => {
    const wrapper = mount(SentinelThreatIntelView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).indicators).toHaveLength(6)
  })

  it('fetchIndicators sets loading false after success', async () => {
    const wrapper = mount(SentinelThreatIntelView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('fetchIndicators handles null value in response', async () => {
    vi.mocked(sentinelThreatIntelApi.list).mockResolvedValue({ value: null } as any)
    const wrapper = mount(SentinelThreatIntelView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).indicators).toEqual([])
  })

  it('fetchIndicators can be called again via refresh button', async () => {
    const wrapper = mount(SentinelThreatIntelView, { global: globalOpts })
    await flushPromises()
    const btn = wrapper.find('button')
    await btn.trigger('click')
    await flushPromises()
    expect(sentinelThreatIntelApi.list).toHaveBeenCalledTimes(2)
  })

  it('patternTypeBadgeClass returns correct class for url', () => {
    const wrapper = mount(SentinelThreatIntelView, { global: globalOpts })
    expect((wrapper.vm as any).patternTypeBadgeClass('url')).toBe('bg-purple-500/15 text-purple-400')
    expect((wrapper.vm as any).patternTypeBadgeClass('URL')).toBe('bg-purple-500/15 text-purple-400')
  })

  it('patternTypeBadgeClass returns correct class for ipv4-addr', () => {
    const wrapper = mount(SentinelThreatIntelView, { global: globalOpts })
    expect((wrapper.vm as any).patternTypeBadgeClass('ipv4-addr')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('patternTypeBadgeClass returns correct class for ipv6-addr', () => {
    const wrapper = mount(SentinelThreatIntelView, { global: globalOpts })
    expect((wrapper.vm as any).patternTypeBadgeClass('ipv6-addr')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('patternTypeBadgeClass returns correct class for domain-name', () => {
    const wrapper = mount(SentinelThreatIntelView, { global: globalOpts })
    expect((wrapper.vm as any).patternTypeBadgeClass('domain-name')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('patternTypeBadgeClass returns correct class for file', () => {
    const wrapper = mount(SentinelThreatIntelView, { global: globalOpts })
    expect((wrapper.vm as any).patternTypeBadgeClass('file')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('patternTypeBadgeClass returns correct class for email-addr', () => {
    const wrapper = mount(SentinelThreatIntelView, { global: globalOpts })
    expect((wrapper.vm as any).patternTypeBadgeClass('email-addr')).toBe('bg-cyan-500/15 text-cyan-400')
  })

  it('patternTypeBadgeClass returns default class for unknown type', () => {
    const wrapper = mount(SentinelThreatIntelView, { global: globalOpts })
    expect((wrapper.vm as any).patternTypeBadgeClass('x509-certificate')).toBe('bg-gray-500/15 text-gray-400')
    expect((wrapper.vm as any).patternTypeBadgeClass('')).toBe('bg-gray-500/15 text-gray-400')
    expect((wrapper.vm as any).patternTypeBadgeClass(null as any)).toBe('bg-gray-500/15 text-gray-400')
  })

  it('renders indicator display names in table', async () => {
    const wrapper = mount(SentinelThreatIntelView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('Malicious IP')
    expect(wrapper.text()).toContain('Phishing URL')
  })

  it('renders source column', async () => {
    const wrapper = mount(SentinelThreatIntelView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('ThreatFeed-A')
    expect(wrapper.text()).toContain('ThreatFeed-B')
  })

  it('shows EmptyState when no indicators returned', async () => {
    vi.mocked(sentinelThreatIntelApi.list).mockResolvedValue({ value: [] } as any)
    const wrapper = mount(SentinelThreatIntelView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.findComponent({ name: 'EmptyState' }).exists()).toBe(true)
  })

  it('shows LoadingSkeleton while loading', () => {
    vi.mocked(sentinelThreatIntelApi.list).mockReturnValue(new Promise(() => {}))
    const wrapper = mount(SentinelThreatIntelView, { global: globalOpts })
    // loading is true initially before the promise resolves
    expect((wrapper.vm as any).loading).toBe(true)
  })

  it('table columns header renders Display Name, Pattern Type, Source, Confidence, Labels, Valid From', async () => {
    const wrapper = mount(SentinelThreatIntelView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('Display Name')
    expect(wrapper.text()).toContain('Pattern Type')
    expect(wrapper.text()).toContain('Source')
    expect(wrapper.text()).toContain('Confidence')
    expect(wrapper.text()).toContain('Labels')
    expect(wrapper.text()).toContain('Valid From')
  })

  it('indicator with more than 3 labels shows overflow count', async () => {
    const wrapper = mount(SentinelThreatIntelView, { global: globalOpts })
    await flushPromises()
    // ti-001 has 4 labels: malware, c2, ransomware, apt -> shows +1
    expect(wrapper.text()).toContain('+1')
  })

  it('indicator with exactly 3 labels shows no overflow count', async () => {
    vi.mocked(sentinelThreatIntelApi.list).mockResolvedValue({
      value: [{
        name: 'ti-x',
        properties: {
          displayName: 'Three Label Indicator',
          pattern: "[url:value = 'http://x.com']",
          patternType: 'url',
          source: 'Test',
          confidence: 50,
          labels: ['a', 'b', 'c'],
          validFrom: '',
        },
      }],
    } as any)
    const wrapper = mount(SentinelThreatIntelView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).not.toContain('+')
  })
})
