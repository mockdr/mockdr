import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/splunk', () => ({
  splunkNotableApi: {
    list: vi.fn().mockResolvedValue([
      {
        event_id: 'notable-1',
        rule_name: 'CrowdStrike - Detection Alert',
        severity: 'high',
        urgency: 'high',
        status: '1',
        status_label: 'New',
        owner: 'unassigned',
        dest: 'WKSTN-002',
        time: String(Date.now() / 1000),
        _time: String(Date.now() / 1000),
        description: 'CS Detection on WKSTN-002',
        drilldown_search: 'search index=crowdstrike',
        rule_title: 'CrowdStrike Detection Alert',
        security_domain: 'endpoint',
        src: '',
        user: 'jdoe',
      },
    ]),
    update: vi.fn().mockResolvedValue({ success: true }),
  },
}))

import SplunkNotablesView from '../../splunk/SplunkNotablesView.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/splunk/notables/:id', component: { template: '<div />' } },
  ],
})

describe('SplunkNotablesView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the notables header', () => {
    const wrapper = mount(SplunkNotablesView, {
      global: { plugins: [router], stubs: { LoadingSkeleton: true } },
    })
    expect(wrapper.text()).toContain('Notable Events')
  })

  it('has status and severity filter dropdowns', () => {
    const wrapper = mount(SplunkNotablesView, {
      global: { plugins: [router], stubs: { LoadingSkeleton: true } },
    })
    const selects = wrapper.findAll('select')
    expect(selects.length).toBeGreaterThanOrEqual(2)
  })
})
