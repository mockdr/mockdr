import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/sentinel', () => ({
  sentinelAlertRuleApi: {
    list: vi.fn(),
  },
}))

import { sentinelAlertRuleApi } from '@/api/sentinel'
import SentinelAnalyticsView from '@/views/sentinel/SentinelAnalyticsView.vue'

const mockRules = [
  {
    name: 'rule-001',
    properties: {
      displayName: 'Brute Force Detection',
      description: 'Detects brute force attacks',
      enabled: true,
      severity: 'High',
      kind: 'Scheduled',
      tactics: ['CredentialAccess', 'Persistence', 'DefenseEvasion', 'Impact'],
    },
  },
  {
    name: 'rule-002',
    properties: {
      displayName: 'Fusion Alert',
      description: 'Machine learning fusion rule',
      enabled: false,
      severity: 'Medium',
      kind: 'Fusion',
      tactics: ['LateralMovement'],
    },
  },
  {
    name: 'rule-003',
    properties: {
      displayName: 'MS Security Incident',
      description: 'Creates incidents from MS security alerts',
      enabled: true,
      severity: 'Low',
      kind: 'MicrosoftSecurityIncidentCreation',
      tactics: [],
    },
  },
  {
    name: 'rule-004',
    properties: {
      displayName: 'NRT Anomaly',
      description: 'Near-real-time anomaly detection',
      enabled: true,
      severity: 'Informational',
      kind: 'NRT',
      tactics: ['Exfiltration', 'CommandAndControl'],
    },
  },
  {
    name: 'rule-005',
    properties: {
      displayName: 'Unknown Kind Rule',
      description: '',
      enabled: false,
      severity: 'High',
      kind: 'CustomKind',
      tactics: null,
    },
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/sentinel/analytics', component: { template: '<div />' } },
  ],
})

const globalOpts = {
  plugins: [router],
  stubs: { LoadingSkeleton: true, EmptyState: true },
}

describe('SentinelAnalyticsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(sentinelAlertRuleApi.list).mockResolvedValue({ value: mockRules } as any)
  })

  it('renders the page header', () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    expect(wrapper.text()).toContain('Analytics Rules')
  })

  it('calls sentinelAlertRuleApi.list on mount', async () => {
    mount(SentinelAnalyticsView, { global: globalOpts })
    await flushPromises()
    expect(sentinelAlertRuleApi.list).toHaveBeenCalledTimes(1)
  })

  it('fetchRules populates rules ref', async () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).rules).toHaveLength(5)
  })

  it('fetchRules sets loading false after success', async () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('fetchRules handles null value in response', async () => {
    vi.mocked(sentinelAlertRuleApi.list).mockResolvedValue({ value: null } as any)
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).rules).toEqual([])
  })

  it('fetchRules can be called again via refresh button', async () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    await flushPromises()
    const btn = wrapper.find('button')
    await btn.trigger('click')
    await flushPromises()
    expect(sentinelAlertRuleApi.list).toHaveBeenCalledTimes(2)
  })

  it('severityBadgeClass returns correct class for high', () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('high')).toBe('bg-red-500/15 text-red-400')
    expect((wrapper.vm as any).severityBadgeClass('High')).toBe('bg-red-500/15 text-red-400')
  })

  it('severityBadgeClass returns correct class for medium', () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('medium')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('severityBadgeClass returns correct class for low', () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('low')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('severityBadgeClass returns correct class for informational', () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('informational')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('severityBadgeClass returns default class for unknown', () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('unknown')).toBe('bg-gray-500/15 text-gray-400')
    expect((wrapper.vm as any).severityBadgeClass('')).toBe('bg-gray-500/15 text-gray-400')
    expect((wrapper.vm as any).severityBadgeClass(null as any)).toBe('bg-gray-500/15 text-gray-400')
  })

  it('kindBadgeClass returns correct class for scheduled', () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    expect((wrapper.vm as any).kindBadgeClass('Scheduled')).toBe('bg-blue-500/15 text-blue-400')
    expect((wrapper.vm as any).kindBadgeClass('scheduled')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('kindBadgeClass returns correct class for fusion', () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    expect((wrapper.vm as any).kindBadgeClass('fusion')).toBe('bg-purple-500/15 text-purple-400')
  })

  it('kindBadgeClass returns correct class for microsoftsecurityincidentcreation', () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    expect((wrapper.vm as any).kindBadgeClass('microsoftsecurityincidentcreation')).toBe('bg-green-500/15 text-green-400')
    expect((wrapper.vm as any).kindBadgeClass('MicrosoftSecurityIncidentCreation')).toBe('bg-green-500/15 text-green-400')
  })

  it('kindBadgeClass returns correct class for nrt', () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    expect((wrapper.vm as any).kindBadgeClass('nrt')).toBe('bg-orange-500/15 text-orange-400')
    expect((wrapper.vm as any).kindBadgeClass('NRT')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('kindBadgeClass returns default class for unknown kind', () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    expect((wrapper.vm as any).kindBadgeClass('CustomKind')).toBe('bg-gray-500/15 text-gray-400')
    expect((wrapper.vm as any).kindBadgeClass('')).toBe('bg-gray-500/15 text-gray-400')
    expect((wrapper.vm as any).kindBadgeClass(null as any)).toBe('bg-gray-500/15 text-gray-400')
  })

  it('kindLabel returns correct label for scheduled', () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    expect((wrapper.vm as any).kindLabel('scheduled')).toBe('Scheduled')
    expect((wrapper.vm as any).kindLabel('Scheduled')).toBe('Scheduled')
  })

  it('kindLabel returns correct label for fusion', () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    expect((wrapper.vm as any).kindLabel('fusion')).toBe('Fusion')
  })

  it('kindLabel returns correct label for microsoftsecurityincidentcreation', () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    expect((wrapper.vm as any).kindLabel('microsoftsecurityincidentcreation')).toBe('MS Security')
  })

  it('kindLabel returns correct label for nrt', () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    expect((wrapper.vm as any).kindLabel('nrt')).toBe('NRT')
  })

  it('kindLabel returns raw kind string for unknown kind', () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    expect((wrapper.vm as any).kindLabel('CustomKind')).toBe('CustomKind')
  })

  it('kindLabel returns -- for empty string', () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    expect((wrapper.vm as any).kindLabel('')).toBe('--')
  })

  it('kindLabel returns -- for null', () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    expect((wrapper.vm as any).kindLabel(null as any)).toBe('--')
  })

  it('renders rule display names in table', async () => {
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('Brute Force Detection')
    expect(wrapper.text()).toContain('Fusion Alert')
  })

  it('shows EmptyState when no rules returned', async () => {
    vi.mocked(sentinelAlertRuleApi.list).mockResolvedValue({ value: [] } as any)
    const wrapper = mount(SentinelAnalyticsView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.findComponent({ name: 'EmptyState' }).exists()).toBe(true)
  })
})
