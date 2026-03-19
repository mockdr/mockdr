import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/splunk', () => ({
  splunkNotableApi: {
    list: vi.fn(),
    update: vi.fn(),
  },
}))

import { splunkNotableApi } from '@/api/splunk'
import SplunkNotableDetailView from '@/views/splunk/SplunkNotableDetailView.vue'

const mockNotable = {
  event_id: 'evt-abc-123',
  rule_name: 'SentinelOne - Ransomware Detected',
  severity: 'critical',
  urgency: 'critical',
  status: '1',
  status_label: 'New',
  owner: 'alice@company.com',
  dest: 'WKSTN-001',
  time: '1700000000',
  _time: '1700000000',
  description: 'Ransomware activity detected on endpoint',
  drilldown_search: 'search index=sentinelone sourcetype=sentinelone:threat',
  rule_title: 'SentinelOne Ransomware',
  security_domain: 'endpoint',
  src: '192.168.1.100',
  user: 'jdoe',
}

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/splunk/notables', component: { template: '<div />' } },
    { path: '/splunk/notables/:id', component: { template: '<div />' } },
  ],
})

const globalOpts = {
  plugins: [router],
  stubs: { LoadingSkeleton: true, RouterLink: true },
}

describe('SplunkNotableDetailView', () => {
  beforeEach(async () => {
    await router.push('/splunk/notables/evt-abc-123')
    await router.isReady()
    vi.clearAllMocks()
    vi.mocked(splunkNotableApi.list).mockResolvedValue([mockNotable] as any)
    vi.mocked(splunkNotableApi.update).mockResolvedValue(undefined as any)
  })

  it('renders the page header', () => {
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    expect(wrapper.text()).toContain('Notable Event Detail')
  })

  it('calls splunkNotableApi.list on mount', async () => {
    mount(SplunkNotableDetailView, { global: globalOpts })
    await flushPromises()
    expect(splunkNotableApi.list).toHaveBeenCalledTimes(1)
  })

  it('fetchNotable finds the notable matching the route id', async () => {
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).notable).toMatchObject({ event_id: 'evt-abc-123' })
  })

  it('fetchNotable sets notable to null when not found', async () => {
    vi.mocked(splunkNotableApi.list).mockResolvedValue([
      { ...mockNotable, event_id: 'different-id' },
    ] as any)
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).notable).toBeNull()
  })

  it('fetchNotable sets loading false after success', async () => {
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('fetchNotable sets loading false even when list is empty', async () => {
    vi.mocked(splunkNotableApi.list).mockResolvedValue([] as any)
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('shows "Notable event not found" when notable is null', async () => {
    vi.mocked(splunkNotableApi.list).mockResolvedValue([] as any)
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('Notable event not found')
  })

  it('renders notable details when found', async () => {
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('SentinelOne - Ransomware Detected')
    expect(wrapper.text()).toContain('evt-abc-123')
    expect(wrapper.text()).toContain('WKSTN-001')
    expect(wrapper.text()).toContain('alice@company.com')
  })

  it('renders drilldown search', async () => {
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('search index=sentinelone sourcetype=sentinelone:threat')
  })

  it('renders description', async () => {
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('Ransomware activity detected on endpoint')
  })

  it('severityBadgeClass returns correct class for critical', () => {
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('critical')).toBe('bg-red-500/15 text-red-400')
    expect((wrapper.vm as any).severityBadgeClass('Critical')).toBe('bg-red-500/15 text-red-400')
  })

  it('severityBadgeClass returns correct class for high', () => {
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('high')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('severityBadgeClass returns correct class for medium', () => {
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('medium')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('severityBadgeClass returns correct class for low', () => {
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('low')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('severityBadgeClass returns default class for unknown severity', () => {
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    expect((wrapper.vm as any).severityBadgeClass('informational')).toBe('bg-gray-500/15 text-gray-400')
    expect((wrapper.vm as any).severityBadgeClass('')).toBe('bg-gray-500/15 text-gray-400')
    expect((wrapper.vm as any).severityBadgeClass(null as any)).toBe('bg-gray-500/15 text-gray-400')
  })

  it('formatTime returns empty string for falsy input', () => {
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    expect((wrapper.vm as any).formatTime('')).toBe('')
    expect((wrapper.vm as any).formatTime(null as any)).toBe('')
    expect((wrapper.vm as any).formatTime(undefined as any)).toBe('')
  })

  it('formatTime converts epoch string to locale date string', () => {
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    const result = (wrapper.vm as any).formatTime('1700000000')
    expect(result).toBeTruthy()
    expect(typeof result).toBe('string')
    expect(result).not.toBe('1700000000')
  })

  it('updateNotable calls splunkNotableApi.update and refetches', async () => {
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    await flushPromises()
    await (wrapper.vm as any).updateNotable('status', '2')
    await flushPromises()
    expect(splunkNotableApi.update).toHaveBeenCalledWith('evt-abc-123', { status: '2' })
    expect(splunkNotableApi.list).toHaveBeenCalledTimes(2)
  })

  it('updateNotable can update different fields', async () => {
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    await flushPromises()
    await (wrapper.vm as any).updateNotable('owner', 'bob@company.com')
    await flushPromises()
    expect(splunkNotableApi.update).toHaveBeenCalledWith('evt-abc-123', { owner: 'bob@company.com' })
  })

  it('addComment does nothing when comment is empty', async () => {
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).comment = ''
    await (wrapper.vm as any).addComment()
    expect(splunkNotableApi.update).not.toHaveBeenCalled()
  })

  it('addComment does nothing when comment is whitespace only', async () => {
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).comment = '   '
    await (wrapper.vm as any).addComment()
    expect(splunkNotableApi.update).not.toHaveBeenCalled()
  })

  it('addComment calls update and clears comment on success', async () => {
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).comment = 'Investigated, looks like FP'
    await (wrapper.vm as any).addComment()
    await flushPromises()
    expect(splunkNotableApi.update).toHaveBeenCalledWith('evt-abc-123', { comment: 'Investigated, looks like FP' })
    expect((wrapper.vm as any).comment).toBe('')
    expect(splunkNotableApi.list).toHaveBeenCalledTimes(2)
  })

  it('addComment refetches after comment submission', async () => {
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).comment = 'Test comment'
    await (wrapper.vm as any).addComment()
    await flushPromises()
    expect(splunkNotableApi.list).toHaveBeenCalledTimes(2)
  })

  it('shows LoadingSkeleton while loading', () => {
    vi.mocked(splunkNotableApi.list).mockReturnValue(new Promise(() => {}))
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    expect(wrapper.findComponent({ name: 'LoadingSkeleton' }).exists()).toBe(true)
  })

  it('shows Add Comment section when notable is loaded', async () => {
    const wrapper = mount(SplunkNotableDetailView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('Add Comment')
  })
})
