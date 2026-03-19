import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/splunk', () => ({
  splunkSearchApi: {
    createJob: vi.fn().mockResolvedValue({ sid: 'test-sid-123' }),
    getJob: vi.fn().mockResolvedValue({
      entry: [
        {
          content: {
            isDone: true,
            eventCount: 2,
            resultCount: 2,
            dispatchState: 'DONE',
          },
        },
      ],
    }),
    getResults: vi.fn().mockResolvedValue({
      results: [
        {
          _time: '2024-11-14T22:13:20.000+00:00',
          index: 'sentinelone',
          sourcetype: 'sentinelone:channel:threats',
          host: 'mockdr',
        },
        {
          _time: '2024-11-14T22:14:00.000+00:00',
          index: 'sentinelone',
          sourcetype: 'sentinelone:channel:threats',
          host: 'mockdr-2',
        },
      ],
      fields: [
        { name: '_time' },
        { name: 'index' },
        { name: 'sourcetype' },
        { name: 'host' },
      ],
      init_offset: 0,
      messages: [],
    }),
  },
}))

import SplunkSearchView from '@/views/splunk/SplunkSearchView.vue'

const STUBS = {
  LoadingSkeleton: true,
  EmptyState: true,
  StatusBadge: true,
  RouterLink: { template: '<a><slot /></a>' },
  Teleport: true,
}

const router = createRouter({
  history: createWebHistory(),
  routes: [{ path: '/', component: { template: '<div />' } }],
})

function mountView() {
  return mount(SplunkSearchView, {
    global: { plugins: [router], stubs: STUBS },
  })
}

describe('SplunkSearchView', () => {
  beforeEach(async () => {
    await router.push('/')
    await router.isReady()
    vi.clearAllMocks()
  })

  it('renders the page header with Splunk Search', () => {
    const wrapper = mountView()
    expect(wrapper.text()).toContain('Splunk Search')
  })

  it('renders the search input', () => {
    const wrapper = mountView()
    expect(wrapper.find('input').exists()).toBe(true)
  })

  it('renders the Search button', () => {
    const wrapper = mountView()
    const buttons = wrapper.findAll('button')
    const searchBtn = buttons.find(b => b.text().includes('Search'))
    expect(searchBtn).toBeTruthy()
  })

  it('has a default query value pre-filled', () => {
    const wrapper = mountView()
    const input = wrapper.find('input')
    expect((input.element as HTMLInputElement).value).toContain('search index=sentinelone')
  })

  it('shows empty state prompt text initially', () => {
    const wrapper = mountView()
    expect(wrapper.text()).toContain('Enter an SPL query')
  })

  it('runSearch does nothing when query is empty', async () => {
    const { splunkSearchApi } = await import('../../../api/splunk')
    const wrapper = mountView()
    const vm = wrapper.vm as any
    vm.query = ''
    await vm.runSearch()
    expect(splunkSearchApi.createJob).not.toHaveBeenCalled()
  })

  it('runSearch does nothing when query is only whitespace', async () => {
    const { splunkSearchApi } = await import('../../../api/splunk')
    const wrapper = mountView()
    const vm = wrapper.vm as any
    vm.query = '   '
    await vm.runSearch()
    expect(splunkSearchApi.createJob).not.toHaveBeenCalled()
  })

  it('runSearch calls createJob with the current query', async () => {
    const { splunkSearchApi } = await import('../../../api/splunk')
    const wrapper = mountView()
    const vm = wrapper.vm as any
    vm.query = 'search index=sentinelone sourcetype=sentinelone:channel:threats | head 20'
    await vm.runSearch()
    await flushPromises()
    expect(splunkSearchApi.createJob).toHaveBeenCalledWith(
      'search index=sentinelone sourcetype=sentinelone:channel:threats | head 20',
    )
  })

  it('runSearch calls getJob with the sid returned from createJob', async () => {
    const { splunkSearchApi } = await import('../../../api/splunk')
    const wrapper = mountView()
    const vm = wrapper.vm as any
    await vm.runSearch()
    await flushPromises()
    expect(splunkSearchApi.getJob).toHaveBeenCalledWith('test-sid-123')
  })

  it('runSearch calls getResults with the sid and limit 100', async () => {
    const { splunkSearchApi } = await import('../../../api/splunk')
    const wrapper = mountView()
    const vm = wrapper.vm as any
    await vm.runSearch()
    await flushPromises()
    expect(splunkSearchApi.getResults).toHaveBeenCalledWith('test-sid-123', 100)
  })

  it('populates results after successful search', async () => {
    const wrapper = mountView()
    const vm = wrapper.vm as any
    await vm.runSearch()
    await flushPromises()
    expect(vm.results.length).toBe(2)
  })

  it('populates fields after successful search', async () => {
    const wrapper = mountView()
    const vm = wrapper.vm as any
    await vm.runSearch()
    await flushPromises()
    expect(vm.fields).toContain('_time')
    expect(vm.fields).toContain('index')
    expect(vm.fields).toContain('sourcetype')
    expect(vm.fields).toContain('host')
  })

  it('sets resultCount to number of results', async () => {
    const wrapper = mountView()
    const vm = wrapper.vm as any
    await vm.runSearch()
    await flushPromises()
    expect(vm.resultCount).toBe(2)
  })

  it('displays result rows in the table after search', async () => {
    const wrapper = mountView()
    const vm = wrapper.vm as any
    await vm.runSearch()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('sentinelone')
    expect(wrapper.text()).toContain('mockdr')
  })

  it('displays result count text after search', async () => {
    const wrapper = mountView()
    const vm = wrapper.vm as any
    await vm.runSearch()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('2 results')
  })

  it('sets loading to false after search completes', async () => {
    const wrapper = mountView()
    const vm = wrapper.vm as any
    const searchPromise = vm.runSearch()
    await flushPromises()
    await searchPromise
    expect(vm.loading).toBe(false)
  })

  it('clears previous results on new search', async () => {
    const wrapper = mountView()
    const vm = wrapper.vm as any
    await vm.runSearch()
    await flushPromises()
    expect(vm.results.length).toBe(2)
    const secondSearch = vm.runSearch()
    expect(vm.results.length).toBe(0)
    await flushPromises()
    await secondSearch
  })

  it('sets error message when createJob throws', async () => {
    const { splunkSearchApi } = await import('../../../api/splunk')
    vi.mocked(splunkSearchApi.createJob).mockRejectedValueOnce(new Error('Connection refused'))
    const wrapper = mountView()
    const vm = wrapper.vm as any
    await vm.runSearch()
    await flushPromises()
    expect(vm.error).toBe('Connection refused')
  })

  it('sets generic error message when non-Error is thrown', async () => {
    const { splunkSearchApi } = await import('../../../api/splunk')
    vi.mocked(splunkSearchApi.createJob).mockRejectedValueOnce('string error')
    const wrapper = mountView()
    const vm = wrapper.vm as any
    await vm.runSearch()
    await flushPromises()
    expect(vm.error).toBe('Search failed')
  })

  it('displays error card when error is set', async () => {
    const { splunkSearchApi } = await import('../../../api/splunk')
    vi.mocked(splunkSearchApi.createJob).mockRejectedValueOnce(new Error('Auth failed'))
    const wrapper = mountView()
    const vm = wrapper.vm as any
    await vm.runSearch()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Auth failed')
  })

  it('clears error on new search attempt', async () => {
    const { splunkSearchApi } = await import('../../../api/splunk')
    vi.mocked(splunkSearchApi.createJob).mockRejectedValueOnce(new Error('First error'))
    const wrapper = mountView()
    const vm = wrapper.vm as any
    await vm.runSearch()
    await flushPromises()
    expect(vm.error).toBe('First error')
    const searchPromise = vm.runSearch()
    expect(vm.error).toBe('')
    await flushPromises()
    await searchPromise
  })

  it('polls getJob until isDone is true', async () => {
    const { splunkSearchApi } = await import('../../../api/splunk')
    vi.mocked(splunkSearchApi.getJob)
      .mockResolvedValueOnce({ entry: [{ name: '', id: '', updated: '', content: { sid: '', dispatchState: 'RUNNING', doneProgress: 0, eventCount: 0, resultCount: 0, isDone: false, isFailed: false } }], links: {}, origin: '', updated: '', generator: { build: '', version: '' }, paging: { total: 0, perPage: 100, offset: 0 } })
      .mockResolvedValueOnce({ entry: [{ name: '', id: '', updated: '', content: { sid: '', dispatchState: 'DONE', doneProgress: 1, eventCount: 0, resultCount: 0, isDone: true, isFailed: false } }], links: {}, origin: '', updated: '', generator: { build: '', version: '' }, paging: { total: 0, perPage: 100, offset: 0 } })
    const wrapper = mountView()
    const vm = wrapper.vm as any
    await vm.runSearch()
    await flushPromises()
    expect(splunkSearchApi.getJob).toHaveBeenCalledTimes(2)
  })

  it('handles getJob response with null entry array', async () => {
    const { splunkSearchApi } = await import('../../../api/splunk')
    vi.mocked(splunkSearchApi.getJob).mockResolvedValueOnce({ entry: null } as unknown as import('../../../types/splunk').SplunkEnvelope<import('../../../types/splunk').SplunkJobStatus>)
    vi.mocked(splunkSearchApi.getJob).mockResolvedValueOnce({
      entry: [{ name: '', id: '', updated: '', content: { sid: '', dispatchState: 'DONE', doneProgress: 1, eventCount: 0, resultCount: 0, isDone: true, isFailed: false } }],
      links: {}, origin: '', updated: '', generator: { build: '', version: '' }, paging: { total: 0, perPage: 100, offset: 0 },
    })
    const wrapper = mountView()
    const vm = wrapper.vm as any
    await vm.runSearch()
    await flushPromises()
    expect(splunkSearchApi.getResults).toHaveBeenCalled()
  })

  it('handles getResults with no fields', async () => {
    const { splunkSearchApi } = await import('../../../api/splunk')
    vi.mocked(splunkSearchApi.getResults).mockResolvedValueOnce({
      results: [{ _raw: 'some raw event' }],
      fields: null as unknown as { name: string }[],
      init_offset: 0,
      messages: [],
    })
    const wrapper = mountView()
    const vm = wrapper.vm as any
    await vm.runSearch()
    await flushPromises()
    expect(vm.fields).toEqual([])
    expect(vm.results.length).toBe(1)
  })

  it('handles getResults with no results', async () => {
    const { splunkSearchApi } = await import('../../../api/splunk')
    vi.mocked(splunkSearchApi.getResults).mockResolvedValueOnce({
      results: null as unknown as Record<string, unknown>[],
      fields: [],
      init_offset: 0,
      messages: [],
    })
    const wrapper = mountView()
    const vm = wrapper.vm as any
    await vm.runSearch()
    await flushPromises()
    expect(vm.results).toEqual([])
    expect(vm.resultCount).toBe(0)
  })

  it('sets loading to false even when an error occurs', async () => {
    const { splunkSearchApi } = await import('../../../api/splunk')
    vi.mocked(splunkSearchApi.createJob).mockRejectedValueOnce(new Error('Timeout'))
    const wrapper = mountView()
    const vm = wrapper.vm as any
    await vm.runSearch()
    await flushPromises()
    expect(vm.loading).toBe(false)
  })

  it('clicking Search button triggers runSearch', async () => {
    const { splunkSearchApi } = await import('../../../api/splunk')
    const wrapper = mountView()
    const buttons = wrapper.findAll('button')
    const searchBtn = buttons.find(b => b.text().includes('Search'))
    await searchBtn!.trigger('click')
    await flushPromises()
    expect(splunkSearchApi.createJob).toHaveBeenCalledTimes(1)
  })
})
