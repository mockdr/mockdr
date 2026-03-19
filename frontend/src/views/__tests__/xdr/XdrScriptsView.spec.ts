import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

const mockScriptsList = vi.hoisted(() => vi.fn())

vi.mock('../../../api/cortex', () => ({
  xdrScriptsApi: { list: mockScriptsList },
}))

vi.mock('../../../utils/formatters', () => ({
  formatEpoch: vi.fn((v) => `${v}`),
  relativeTime: vi.fn((v) => v ?? ''),
}))

import XdrScriptsView from '@/views/xdr/XdrScriptsView.vue'
import { xdrScriptsApi } from '@/api/cortex'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/xdr/scripts', component: { template: '<div />' } },
  ],
})

const stubs = { LoadingSkeleton: true, EmptyState: true }

const FAKE_SCRIPTS = [
  { script_id: 'script-1', name: 'Collect Artifacts', description: 'Collects system artifacts', created_by: 'admin', created_date: 1700000000000, modified_date: 1700000001000, script_hash: 'abc123', os_type: ['WINDOWS'], script_type: ['powershell'] },
  { script_id: 'script-2', name: 'Kill Process', description: 'Terminates processes', created_by: 'analyst', created_date: 1700000002000, modified_date: 1700000003000, script_hash: 'def456', os_type: ['LINUX', 'MACOS'], script_type: ['bash'] },
]

describe('XdrScriptsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockScriptsList.mockResolvedValue({ reply: { scripts: FAKE_SCRIPTS, total_count: 2, result_count: 2 } })
  })

  it('renders the page header', () => {
    const wrapper = mount(XdrScriptsView, { global: { plugins: [router], stubs } })
    expect(wrapper.text()).toContain('Scripts')
  })

  it('calls xdrScriptsApi.list on mount', async () => {
    mount(XdrScriptsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(xdrScriptsApi.list).toHaveBeenCalled()
  })

  it('renders script names after loading', async () => {
    const wrapper = mount(XdrScriptsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('Collect Artifacts')
    expect(wrapper.text()).toContain('Kill Process')
  })

  it('renders script IDs', async () => {
    const wrapper = mount(XdrScriptsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect(wrapper.text()).toContain('script-1')
  })

  it('sets loading to false after fetch', async () => {
    const wrapper = mount(XdrScriptsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('populates scripts array from API', async () => {
    const wrapper = mount(XdrScriptsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).scripts).toHaveLength(2)
  })

  it('riskBadgeClass returns red for high risk (true)', () => {
    const wrapper = mount(XdrScriptsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).riskBadgeClass(true)).toContain('red')
  })

  it('riskBadgeClass returns green for low risk (false)', () => {
    const wrapper = mount(XdrScriptsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).riskBadgeClass(false)).toContain('green')
  })

  it('typeBadgeClass returns purple for powershell', () => {
    const wrapper = mount(XdrScriptsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).typeBadgeClass('powershell')).toContain('purple')
  })

  it('typeBadgeClass returns yellow for shell', () => {
    const wrapper = mount(XdrScriptsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).typeBadgeClass('shell')).toContain('yellow')
  })

  it('typeBadgeClass returns blue for python', () => {
    const wrapper = mount(XdrScriptsView, { global: { plugins: [router], stubs } })
    expect((wrapper.vm as any).typeBadgeClass('python')).toContain('blue')
  })

  it('typeBadgeClass returns default for unknown type', () => {
    const wrapper = mount(XdrScriptsView, { global: { plugins: [router], stubs } })
    const result = (wrapper.vm as any).typeBadgeClass('unknown')
    expect(typeof result).toBe('string')
  })

  it('totalCount is set from API total_count', async () => {
    const wrapper = mount(XdrScriptsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).totalCount).toBe(2)
  })

  it('handles empty scripts list gracefully', async () => {
    mockScriptsList.mockResolvedValueOnce({ reply: { scripts: [], total_count: 0 } })
    const wrapper = mount(XdrScriptsView, { global: { plugins: [router], stubs } })
    await flushPromises()
    expect((wrapper.vm as any).scripts).toHaveLength(0)
  })
})
