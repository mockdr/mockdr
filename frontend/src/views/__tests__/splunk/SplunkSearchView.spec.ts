import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/splunk', () => ({
  splunkSearchApi: {
    createJob: vi.fn().mockResolvedValue({ sid: 'test-sid-123' }),
    getResults: vi.fn().mockResolvedValue({
      results: [
        { _time: '1710590400', index: 'sentinelone', sourcetype: 'sentinelone:channel:threats', host: 'mockdr' },
      ],
      fields: [{ name: '_time' }, { name: 'index' }, { name: 'sourcetype' }, { name: 'host' }],
      init_offset: 0,
      messages: [],
    }),
  },
}))

import SplunkSearchView from '../../splunk/SplunkSearchView.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [{ path: '/', component: { template: '<div />' } }],
})

describe('SplunkSearchView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the search input', () => {
    const wrapper = mount(SplunkSearchView, {
      global: { plugins: [router] },
    })
    expect(wrapper.find('input').exists()).toBe(true)
    expect(wrapper.text()).toContain('Splunk Search')
  })

  it('has a search button', () => {
    const wrapper = mount(SplunkSearchView, {
      global: { plugins: [router] },
    })
    expect(wrapper.find('button').text()).toContain('Search')
  })
})
