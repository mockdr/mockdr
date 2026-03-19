import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/defender', () => ({
  ensureMdeAuth: vi.fn().mockResolvedValue(undefined),
  mdeMachinesApi: {
    list: vi.fn().mockResolvedValue({
      value: [
        {
          machineId: 'machine-1',
          computerDnsName: 'WKSTN-001',
          healthStatus: 'Active',
          osPlatform: 'Windows10',
          riskScore: 'High',
        },
        {
          machineId: 'machine-2',
          computerDnsName: 'SRV-002',
          healthStatus: 'Inactive',
          osPlatform: 'Windows10',
          riskScore: 'Medium',
        },
        {
          machineId: 'machine-3',
          computerDnsName: 'LINUX-003',
          healthStatus: 'Active',
          osPlatform: 'Linux',
          riskScore: 'Low',
        },
      ],
    }),
  },
  mdeAlertsApi: {
    list: vi.fn().mockResolvedValue({
      value: [
        {
          alertId: 'alert-1',
          title: 'Alert One',
          severity: 'High',
          status: 'New',
          category: 'Malware',
          creationTime: '2025-01-10T00:00:00Z',
          machineId: 'machine-1',
          computerDnsName: 'WKSTN-001',
        },
        {
          alertId: 'alert-2',
          title: 'Alert Two',
          severity: 'Medium',
          status: 'InProgress',
          category: 'CommandAndControl',
          creationTime: '2025-01-11T00:00:00Z',
          machineId: 'machine-2',
          computerDnsName: 'SRV-002',
        },
        {
          alertId: 'alert-3',
          title: 'Alert Three',
          severity: 'Low',
          status: 'Resolved',
          category: 'Execution',
          creationTime: '2025-01-12T00:00:00Z',
          machineId: 'machine-3',
          computerDnsName: 'LINUX-003',
        },
        {
          alertId: 'alert-4',
          title: 'Alert Four',
          severity: 'Informational',
          status: 'New',
          category: 'PolicyViolation',
          creationTime: '2025-01-13T00:00:00Z',
          machineId: 'machine-1',
          computerDnsName: 'WKSTN-001',
        },
      ],
    }),
  },
  mdeIndicatorsApi: {
    list: vi.fn().mockResolvedValue({
      value: [
        { indicatorId: 'ind-1', indicatorValue: '1.2.3.4', indicatorType: 'IpAddress', action: 'AlertAndBlock', severity: 'High', title: 'Bad IP' },
        { indicatorId: 'ind-2', indicatorValue: 'evil.com', indicatorType: 'DomainName', action: 'Alert', severity: 'Medium', title: 'Bad Domain' },
      ],
    }),
  },
}))

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

import MdeDashboardView from '@/views/mde/MdeDashboardView.vue'
import { ensureMdeAuth, mdeMachinesApi, mdeAlertsApi, mdeIndicatorsApi } from '@/api/defender'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/defender/machines', component: { template: '<div />' } },
    { path: '/defender/alerts', component: { template: '<div />' } },
    { path: '/defender/indicators', component: { template: '<div />' } },
  ],
})

const STUBS = {
  LoadingSkeleton: true,
  RouterLink: { template: '<a><slot /></a>' },
  Doughnut: { template: '<div class="mock-doughnut" />', props: ['data', 'options'] },
}

describe('MdeDashboardView', () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    await router.push('/')
    await router.isReady()
  })

  it('renders the page header with Defender Dashboard title', async () => {
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Defender Dashboard')
  })

  it('calls ensureMdeAuth on mount', async () => {
    mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(ensureMdeAuth).toHaveBeenCalled()
  })

  it('calls all three APIs on mount', async () => {
    mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(mdeMachinesApi.list).toHaveBeenCalledWith({ $top: 50 })
    expect(mdeAlertsApi.list).toHaveBeenCalledWith({ $top: 50 })
    expect(mdeIndicatorsApi.list).toHaveBeenCalledWith({ $top: 0 })
  })

  it('sets loading to false after fetchAll completes', async () => {
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('sets machineCount, alertCount, and indicatorCount from API responses', async () => {
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).machineCount).toBe(3)
    expect((wrapper.vm as any).alertCount).toBe(4)
    expect((wrapper.vm as any).indicatorCount).toBe(2)
  })

  it('fetchAll sets error message on API failure', async () => {
    vi.mocked(mdeMachinesApi.list).mockRejectedValueOnce(new Error('Network failure'))
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('Network failure')
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('fetchAll sets fallback error string when non-Error is thrown', async () => {
    vi.mocked(mdeMachinesApi.list).mockRejectedValueOnce('plain string error')
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('Failed to fetch data')
  })

  it('fetchAll can be called explicitly and refreshes counts', async () => {
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    vi.mocked(mdeMachinesApi.list).mockClear()
    vi.mocked(mdeAlertsApi.list).mockClear()
    vi.mocked(mdeIndicatorsApi.list).mockClear()
    await (wrapper.vm as any).fetchAll()
    await flushPromises()
    expect(mdeMachinesApi.list).toHaveBeenCalled()
    expect(mdeAlertsApi.list).toHaveBeenCalled()
    expect(mdeIndicatorsApi.list).toHaveBeenCalled()
  })

  it('fetchAll clears the error field before re-fetching', async () => {
    vi.mocked(mdeMachinesApi.list).mockRejectedValueOnce(new Error('First error'))
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('First error')

    // Successful re-fetch clears the error
    await (wrapper.vm as any).fetchAll()
    await flushPromises()
    expect((wrapper.vm as any).error).toBe('')
  })

  it('fetchAll falls back to empty arrays when value is null', async () => {
    vi.mocked(mdeMachinesApi.list).mockResolvedValueOnce({ '@odata.context': '', value: null as unknown as import('../../../types/defender').MdeMachine[] })
    vi.mocked(mdeAlertsApi.list).mockResolvedValueOnce({ '@odata.context': '', value: null as unknown as import('../../../types/defender').MdeAlert[] })
    vi.mocked(mdeIndicatorsApi.list).mockResolvedValueOnce({ '@odata.context': '', value: null as unknown as import('../../../types/defender').MdeIndicator[] })
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).machines).toEqual([])
    expect((wrapper.vm as any).alerts).toEqual([])
    expect((wrapper.vm as any).machineCount).toBe(0)
    expect((wrapper.vm as any).alertCount).toBe(0)
    expect((wrapper.vm as any).indicatorCount).toBe(0)
  })

  // summaryCards computed property
  it('summaryCards computed returns three cards with correct labels', async () => {
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const cards = (wrapper.vm as any).summaryCards
    expect(cards).toHaveLength(3)
    expect(cards[0].label).toBe('Total Machines')
    expect(cards[1].label).toBe('Alerts')
    expect(cards[2].label).toBe('Indicators')
  })

  it('summaryCards reflects updated counts', async () => {
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const cards = (wrapper.vm as any).summaryCards
    expect(cards[0].value).toBe(3)
    expect(cards[1].value).toBe(4)
    expect(cards[2].value).toBe(2)
  })

  // platformChartData computed property
  it('platformChartData groups machines by osPlatform', async () => {
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const chartData = (wrapper.vm as any).platformChartData
    expect(chartData.labels).toContain('Windows10')
    expect(chartData.labels).toContain('Linux')
    // Windows10 count = 2, Linux count = 1
    const win10Index = chartData.labels.indexOf('Windows10')
    const linuxIndex = chartData.labels.indexOf('Linux')
    expect(chartData.datasets[0].data[win10Index]).toBe(2)
    expect(chartData.datasets[0].data[linuxIndex]).toBe(1)
  })

  it('platformChartData uses Unknown for machines with null osPlatform', async () => {
    vi.mocked(mdeMachinesApi.list).mockResolvedValueOnce({
      '@odata.context': '',
      value: [
        { machineId: 'x1', computerDnsName: 'HOST-1', healthStatus: 'Active', osPlatform: null as unknown as string, riskScore: 'None', osVersion: '', exposureLevel: '', lastSeen: '', lastIpAddress: '', lastExternalIpAddress: '', machineTags: [], agentVersion: '', isAadJoined: false, aadDeviceId: '', rbacGroupId: 0, rbacGroupName: '', firstSeen: '' },
      ],
    })
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const chartData = (wrapper.vm as any).platformChartData
    expect(chartData.labels).toContain('Unknown')
  })

  it('platformChartData returns empty labels/data when no machines', async () => {
    vi.mocked(mdeMachinesApi.list).mockResolvedValueOnce({ '@odata.context': '', value: [] })
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const chartData = (wrapper.vm as any).platformChartData
    expect(chartData.labels).toHaveLength(0)
    expect(chartData.datasets[0].data).toHaveLength(0)
  })

  // severityChartData computed property
  it('severityChartData only includes severities with count > 0', async () => {
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const chartData = (wrapper.vm as any).severityChartData
    // alerts have High=1, Medium=1, Low=1, Informational=1
    expect(chartData.labels).toContain('High')
    expect(chartData.labels).toContain('Medium')
    expect(chartData.labels).toContain('Low')
    expect(chartData.labels).toContain('Informational')
    chartData.datasets[0].data.forEach((count: number) => {
      expect(count).toBeGreaterThan(0)
    })
  })

  it('severityChartData excludes severities with count 0', async () => {
    vi.mocked(mdeAlertsApi.list).mockResolvedValueOnce({
      '@odata.context': '',
      value: [
        { alertId: 'a1', title: 'Only High', severity: 'High', status: 'New', category: 'Malware', creationTime: '2025-01-10T00:00:00Z', machineId: 'm1', computerDnsName: 'HOST-1', description: '', detectionSource: '', threatFamilyName: '', assignedTo: '', lastUpdateTime: '2025-01-10T00:00:00Z', resolvedTime: '', classification: '', determination: '' },
      ],
    })
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const chartData = (wrapper.vm as any).severityChartData
    expect(chartData.labels).toContain('High')
    expect(chartData.labels).not.toContain('Medium')
    expect(chartData.labels).not.toContain('Low')
    expect(chartData.labels).not.toContain('Informational')
  })

  it('severityChartData counts unknown severity under its own key', async () => {
    vi.mocked(mdeAlertsApi.list).mockResolvedValueOnce({
      '@odata.context': '',
      value: [
        { alertId: 'a1', title: 'Unknown sev', severity: 'Unknown', status: 'New', category: 'Other', creationTime: '2025-01-10T00:00:00Z', machineId: 'm1', computerDnsName: 'HOST-1', description: '', detectionSource: '', threatFamilyName: '', assignedTo: '', lastUpdateTime: '2025-01-10T00:00:00Z', resolvedTime: '', classification: '', determination: '' },
      ],
    })
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const chartData = (wrapper.vm as any).severityChartData
    expect(chartData.labels).toContain('Unknown')
  })

  it('severityChartData returns empty when no alerts', async () => {
    vi.mocked(mdeAlertsApi.list).mockResolvedValueOnce({ '@odata.context': '', value: [] })
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const chartData = (wrapper.vm as any).severityChartData
    expect(chartData.labels).toHaveLength(0)
    expect(chartData.datasets[0].data).toHaveLength(0)
  })

  // riskChartData computed property
  it('riskChartData groups machines by riskScore', async () => {
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const chartData = (wrapper.vm as any).riskChartData
    expect(chartData.labels).toContain('High')
    expect(chartData.labels).toContain('Medium')
    expect(chartData.labels).toContain('Low')
  })

  it('riskChartData uses None for machines with null riskScore', async () => {
    vi.mocked(mdeMachinesApi.list).mockResolvedValueOnce({
      '@odata.context': '',
      value: [
        { machineId: 'x1', computerDnsName: 'HOST-1', healthStatus: 'Active', osPlatform: 'Linux', riskScore: null as unknown as string, osVersion: '', exposureLevel: '', lastSeen: '', lastIpAddress: '', lastExternalIpAddress: '', machineTags: [], agentVersion: '', isAadJoined: false, aadDeviceId: '', rbacGroupId: 0, rbacGroupName: '', firstSeen: '' },
      ],
    })
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const chartData = (wrapper.vm as any).riskChartData
    expect(chartData.labels).toContain('None')
  })

  it('riskChartData returns empty when no machines', async () => {
    vi.mocked(mdeMachinesApi.list).mockResolvedValueOnce({ '@odata.context': '', value: [] })
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const chartData = (wrapper.vm as any).riskChartData
    expect(chartData.labels).toHaveLength(0)
    expect(chartData.datasets[0].data).toHaveLength(0)
  })

  // Rendered content
  it('shows summary card labels in the DOM', async () => {
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Total Machines')
    expect(wrapper.text()).toContain('Alerts')
    expect(wrapper.text()).toContain('Indicators')
  })

  it('shows recent alert titles in the alerts panel', async () => {
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Alert One')
    expect(wrapper.text()).toContain('Alert Two')
  })

  it('shows machine names in the machines panel', async () => {
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('WKSTN-001')
    expect(wrapper.text()).toContain('SRV-002')
  })

  it('shows error banner when fetchAll fails', async () => {
    vi.mocked(mdeMachinesApi.list).mockRejectedValueOnce(new Error('Auth failed'))
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Auth failed')
  })

  it('Refresh button calls fetchAll', async () => {
    const wrapper = mount(MdeDashboardView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    vi.mocked(mdeMachinesApi.list).mockClear()
    const refreshBtn = wrapper.findAll('button').find(b => b.text().includes('Refresh'))
    expect(refreshBtn).toBeDefined()
    await refreshBtn!.trigger('click')
    await flushPromises()
    expect(mdeMachinesApi.list).toHaveBeenCalled()
  })
})
