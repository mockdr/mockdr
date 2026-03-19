import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/splunk', () => ({
  splunkIndexApi: {
    list: vi.fn(),
  },
}))

import { splunkIndexApi } from '@/api/splunk'
import SplunkIndexesView from '@/views/splunk/SplunkIndexesView.vue'

const mockIndexes = [
  {
    name: 'main',
    content: {
      totalEventCount: '50000',
      currentDBSizeMB: '512',
      datatype: 'event',
      disabled: false,
    },
  },
  {
    name: 'sentinelone',
    content: {
      totalEventCount: '12000',
      currentDBSizeMB: '128',
      datatype: 'event',
      disabled: false,
    },
  },
  {
    name: 'crowdstrike',
    content: {
      totalEventCount: '8000',
      currentDBSizeMB: '80',
      datatype: 'event',
      disabled: true,
    },
  },
  {
    name: 'internal',
    content: {
      totalEventCount: '200',
      currentDBSizeMB: '2',
      datatype: 'metric',
      disabled: false,
    },
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/splunk/indexes', component: { template: '<div />' } },
  ],
})

const globalOpts = {
  plugins: [router],
  stubs: { LoadingSkeleton: true },
}

describe('SplunkIndexesView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(splunkIndexApi.list).mockResolvedValue({ entry: mockIndexes } as any)
  })

  it('renders the page header', () => {
    const wrapper = mount(SplunkIndexesView, { global: globalOpts })
    expect(wrapper.text()).toContain('Splunk Indexes')
  })

  it('calls splunkIndexApi.list on mount', async () => {
    mount(SplunkIndexesView, { global: globalOpts })
    await flushPromises()
    expect(splunkIndexApi.list).toHaveBeenCalledTimes(1)
  })

  it('fetchIndexes populates indexes ref', async () => {
    const wrapper = mount(SplunkIndexesView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).indexes).toHaveLength(4)
  })

  it('fetchIndexes sets loading false after success', async () => {
    const wrapper = mount(SplunkIndexesView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('fetchIndexes clears error on success', async () => {
    const wrapper = mount(SplunkIndexesView, { global: globalOpts })
    ;(wrapper.vm as any).error = 'previous error'
    await (wrapper.vm as any).fetchIndexes()
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('')
  })

  it('fetchIndexes handles null entry in response', async () => {
    vi.mocked(splunkIndexApi.list).mockResolvedValue({ entry: null } as any)
    const wrapper = mount(SplunkIndexesView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).indexes).toEqual([])
  })

  it('fetchIndexes sets error on API failure with Error', async () => {
    vi.mocked(splunkIndexApi.list).mockRejectedValue(new Error('Connection timeout'))
    const wrapper = mount(SplunkIndexesView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('Connection timeout')
  })

  it('fetchIndexes sets generic error for non-Error throws', async () => {
    vi.mocked(splunkIndexApi.list).mockRejectedValue('unknown')
    const wrapper = mount(SplunkIndexesView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('Failed to fetch indexes')
  })

  it('fetchIndexes sets loading false even after error', async () => {
    vi.mocked(splunkIndexApi.list).mockRejectedValue(new Error('fail'))
    const wrapper = mount(SplunkIndexesView, { global: globalOpts })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('fetchIndexes can be called again via refresh button', async () => {
    const wrapper = mount(SplunkIndexesView, { global: globalOpts })
    await flushPromises()
    const btn = wrapper.find('button')
    await btn.trigger('click')
    await flushPromises()
    expect(splunkIndexApi.list).toHaveBeenCalledTimes(2)
  })

  it('renders index names in the table', async () => {
    const wrapper = mount(SplunkIndexesView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('main')
    expect(wrapper.text()).toContain('sentinelone')
    expect(wrapper.text()).toContain('crowdstrike')
  })

  it('renders event counts', async () => {
    const wrapper = mount(SplunkIndexesView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('50000')
    expect(wrapper.text()).toContain('12000')
  })

  it('renders DB size MB values', async () => {
    const wrapper = mount(SplunkIndexesView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('512')
    expect(wrapper.text()).toContain('128')
  })

  it('renders datatype values', async () => {
    const wrapper = mount(SplunkIndexesView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('event')
    expect(wrapper.text()).toContain('metric')
  })

  it('shows Active status for enabled index', async () => {
    const wrapper = mount(SplunkIndexesView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('Active')
  })

  it('shows Disabled status for disabled index', async () => {
    const wrapper = mount(SplunkIndexesView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('Disabled')
  })

  it('renders correct table column headers', async () => {
    const wrapper = mount(SplunkIndexesView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('Index Name')
    expect(wrapper.text()).toContain('Event Count')
    expect(wrapper.text()).toContain('Size (MB)')
    expect(wrapper.text()).toContain('Data Type')
    expect(wrapper.text()).toContain('Status')
  })

  it('shows error banner when error is set', async () => {
    vi.mocked(splunkIndexApi.list).mockRejectedValue(new Error('Server down'))
    const wrapper = mount(SplunkIndexesView, { global: globalOpts })
    await flushPromises()
    expect(wrapper.text()).toContain('Server down')
  })

  it('shows LoadingSkeleton while loading', () => {
    vi.mocked(splunkIndexApi.list).mockReturnValue(new Promise(() => {}))
    const wrapper = mount(SplunkIndexesView, { global: globalOpts })
    expect(wrapper.findComponent({ name: 'LoadingSkeleton' }).exists()).toBe(true)
  })

  it('description text is rendered', () => {
    const wrapper = mount(SplunkIndexesView, { global: globalOpts })
    expect(wrapper.text()).toContain('indexes')
  })
})
