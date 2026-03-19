import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/splunk', () => ({
  splunkHecApi: {
    listTokens: vi.fn(),
    health: vi.fn(),
    submitEvent: vi.fn(),
  },
}))

import { splunkHecApi } from '@/api/splunk'
import SplunkHecView from '@/views/splunk/SplunkHecView.vue'

const mockTokens = [
  {
    name: 'main-hec',
    content: {
      token: 'token-abc-123',
      index: 'main',
      sourcetype: 'json',
      disabled: false,
    },
  },
  {
    name: 'disabled-hec',
    content: {
      token: 'token-def-456',
      index: 'security',
      sourcetype: '',
      disabled: true,
    },
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/splunk/hec', component: { template: '<div />' } },
  ],
})

const globalOpts = {
  plugins: [router],
  stubs: { LoadingSkeleton: true },
}

describe('SplunkHecView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(splunkHecApi.listTokens).mockResolvedValue({ entry: mockTokens } as any)
    vi.mocked(splunkHecApi.health).mockResolvedValue({ text: 'HEC is healthy' } as any)
    vi.mocked(splunkHecApi.submitEvent).mockResolvedValue({ text: 'Success', code: 0 } as any)
  })

  it('renders the page header', () => {
    const wrapper = mount(SplunkHecView, { global: globalOpts })
    expect(wrapper.text()).toContain('HTTP Event Collector')
  })

  it('calls listTokens and health on mount', async () => {
    mount(SplunkHecView, { global: globalOpts })
    await flushPromises()
    expect(splunkHecApi.listTokens).toHaveBeenCalledTimes(1)
    expect(splunkHecApi.health).toHaveBeenCalledTimes(1)
  })

  it('fetchTokens populates tokens ref', async () => {
    const wrapper = mount(SplunkHecView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).tokens).toHaveLength(2)
  })

  it('fetchTokens sets healthStatus from health response', async () => {
    const wrapper = mount(SplunkHecView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).healthStatus).toBe('HEC is healthy')
  })

  it('fetchTokens sets loading false after success', async () => {
    const wrapper = mount(SplunkHecView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('fetchTokens sets error on API failure', async () => {
    vi.mocked(splunkHecApi.listTokens).mockRejectedValue(new Error('Connection refused'))
    const wrapper = mount(SplunkHecView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('Connection refused')
  })

  it('fetchTokens sets generic error for non-Error throws', async () => {
    vi.mocked(splunkHecApi.listTokens).mockRejectedValue('oops')
    const wrapper = mount(SplunkHecView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('Failed to fetch HEC data')
  })

  it('fetchTokens handles null entry in response', async () => {
    vi.mocked(splunkHecApi.listTokens).mockResolvedValue({ entry: null } as any)
    const wrapper = mount(SplunkHecView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).tokens).toEqual([])
  })

  it('fetchTokens handles missing text in health response', async () => {
    vi.mocked(splunkHecApi.health).mockResolvedValue({} as any)
    const wrapper = mount(SplunkHecView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).healthStatus).toBe('Unknown')
  })

  it('fetchTokens can be called via refresh button', async () => {
    const wrapper = mount(SplunkHecView, { global: globalOpts })
    await flushPromises()
    const btn = wrapper.find('button')
    await btn.trigger('click')
    await flushPromises()
    expect(splunkHecApi.listTokens).toHaveBeenCalledTimes(2)
  })

  it('renders token names in the table', async () => {
    const wrapper = mount(SplunkHecView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('main-hec')
    expect(wrapper.text()).toContain('disabled-hec')
  })

  it('renders token values in table', async () => {
    const wrapper = mount(SplunkHecView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('token-abc-123')
  })

  it('shows Active status for enabled token', async () => {
    const wrapper = mount(SplunkHecView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('Active')
  })

  it('shows Disabled status for disabled token', async () => {
    const wrapper = mount(SplunkHecView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('Disabled')
  })

  it('shows health status text', async () => {
    const wrapper = mount(SplunkHecView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('HEC is healthy')
  })

  it('submitTestEvent sets error when no token selected', async () => {
    const wrapper = mount(SplunkHecView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).testToken = ''
    await (wrapper.vm as any).submitTestEvent()
    expect((wrapper.vm as any).submitResult).toBe('Select a token first')
    expect(splunkHecApi.submitEvent).not.toHaveBeenCalled()
  })

  it('submitTestEvent calls splunkHecApi.submitEvent with correct args', async () => {
    const wrapper = mount(SplunkHecView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).testToken = 'token-abc-123'
    ;(wrapper.vm as any).testEvent = '{"message": "hello"}'
    await (wrapper.vm as any).submitTestEvent()
    expect(splunkHecApi.submitEvent).toHaveBeenCalledWith('token-abc-123', { message: 'hello' })
  })

  it('submitTestEvent sets success result after successful submission', async () => {
    const wrapper = mount(SplunkHecView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).testToken = 'token-abc-123'
    ;(wrapper.vm as any).testEvent = '{"message": "hello"}'
    await (wrapper.vm as any).submitTestEvent()
    await flushPromises()
    expect((wrapper.vm as any).submitResult).toContain('Success')
    expect((wrapper.vm as any).submitResult).toContain('code: 0')
  })

  it('submitTestEvent sets error result on API failure', async () => {
    vi.mocked(splunkHecApi.submitEvent).mockRejectedValue(new Error('Token invalid'))
    const wrapper = mount(SplunkHecView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).testToken = 'token-abc-123'
    ;(wrapper.vm as any).testEvent = '{"message": "hello"}'
    await (wrapper.vm as any).submitTestEvent()
    await flushPromises()
    expect((wrapper.vm as any).submitResult).toBe('Token invalid')
  })

  it('submitTestEvent sets generic error for non-Error throws', async () => {
    vi.mocked(splunkHecApi.submitEvent).mockRejectedValue('network fail')
    const wrapper = mount(SplunkHecView, { global: globalOpts })
    await flushPromises()
    ;(wrapper.vm as any).testToken = 'token-abc-123'
    ;(wrapper.vm as any).testEvent = '{"message": "hello"}'
    await (wrapper.vm as any).submitTestEvent()
    await flushPromises()
    expect((wrapper.vm as any).submitResult).toBe('Failed to submit event')
  })

  it('shows error banner when error is set', async () => {
    vi.mocked(splunkHecApi.listTokens).mockRejectedValue(new Error('Server error'))
    const wrapper = mount(SplunkHecView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('Server error')
  })

  it('renders "Submit Test Event" section', () => {
    const wrapper = mount(SplunkHecView, { global: globalOpts })
    expect(wrapper.text()).toContain('Submit Test Event')
  })
})
