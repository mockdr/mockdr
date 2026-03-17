import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

// Mock the API modules
vi.mock('../../../api/splunk', () => ({
  splunkNotableApi: {
    list: vi.fn().mockResolvedValue([
      {
        event_id: 'test-1',
        rule_name: 'SentinelOne - Threat Detected',
        severity: 'critical',
        urgency: 'critical',
        status: '1',
        status_label: 'New',
        owner: 'unassigned',
        dest: 'WKSTN-001',
        time: String(Date.now() / 1000),
        _time: String(Date.now() / 1000),
        description: 'Test threat',
        drilldown_search: 'search index=sentinelone',
        rule_title: 'Test',
        security_domain: 'endpoint',
        src: '',
        user: 'admin',
      },
    ]),
  },
  splunkIndexApi: {
    list: vi.fn().mockResolvedValue({
      entry: [
        { name: 'sentinelone', content: { totalEventCount: '100', currentDBSizeMB: '1.5', datatype: 'event', disabled: false } },
        { name: 'crowdstrike', content: { totalEventCount: '80', currentDBSizeMB: '1.2', datatype: 'event', disabled: false } },
      ],
      paging: { total: 2, perPage: 30, offset: 0 },
    }),
  },
}))

// Mock chart.js to avoid canvas issues
vi.mock('vue-chartjs', () => ({
  Doughnut: { template: '<div class="mock-doughnut" />', props: ['data', 'options'] },
  Bar: { template: '<div class="mock-bar" />', props: ['data', 'options'] },
}))

vi.mock('chart.js', () => ({
  Chart: { register: vi.fn() },
  ArcElement: {},
  Tooltip: {},
  Legend: {},
  BarElement: {},
  CategoryScale: {},
  LinearScale: {},
}))

import SplunkDashboardView from '../../splunk/SplunkDashboardView.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/splunk/notables', component: { template: '<div />' } },
    { path: '/splunk/notables/:id', component: { template: '<div />' } },
  ],
})

describe('SplunkDashboardView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the dashboard header', async () => {
    const wrapper = mount(SplunkDashboardView, {
      global: { plugins: [router], stubs: { LoadingSkeleton: true } },
    })
    expect(wrapper.text()).toContain('Splunk SIEM Dashboard')
  })

  it('shows summary cards', async () => {
    const wrapper = mount(SplunkDashboardView, {
      global: { plugins: [router], stubs: { LoadingSkeleton: true } },
    })
    // Wait for data fetch
    await vi.dynamicImportSettled()
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('Total Events')
    expect(wrapper.text()).toContain('Notable Events (Open)')
    expect(wrapper.text()).toContain('Indexes')
  })
})
