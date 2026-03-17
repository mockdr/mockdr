import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import AlertsView from '../AlertsView.vue'

const mockAlertsList = vi.hoisted(() => vi.fn())

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../api/alerts', () => ({
  alertsApi: {
    list: mockAlertsList,
  },
}))

const FAKE_ALERTS = [
  {
    alertInfo: { alertId: 'a1', source: 'STAR', incidentStatus: 'Unresolved', createdAt: '2025-06-01T12:00:00Z' },
    ruleInfo: { name: 'Suspicious PowerShell', severity: 'High', description: 'Detected encoded command' },
    agentRealtimeInfo: { agentComputerName: 'WS-FINANCE-01' },
  },
  {
    alertInfo: { alertId: 'a2', source: 'Engine', incidentStatus: 'Resolved', createdAt: '2025-06-02T08:00:00Z' },
    ruleInfo: { name: 'Lateral Movement', severity: 'Critical', description: 'PsExec detected' },
    agentRealtimeInfo: { agentComputerName: 'DC-PRIMARY' },
  },
]

describe('AlertsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockAlertsList.mockResolvedValue({
      data: FAKE_ALERTS,
      pagination: { totalItems: 2, nextCursor: null },
    })
  })

  it('renders without error', async () => {
    const w = shallowMount(AlertsView)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the Alerts heading', async () => {
    const w = shallowMount(AlertsView)
    await flushPromises()
    expect(w.text()).toContain('Alerts')
  })

  it('calls alertsApi.list on mount', async () => {
    shallowMount(AlertsView)
    await flushPromises()
    expect(mockAlertsList).toHaveBeenCalledOnce()
  })

  it('renders alert rule names after load', async () => {
    const w = shallowMount(AlertsView)
    await flushPromises()
    expect(w.text()).toContain('Suspicious PowerShell')
    expect(w.text()).toContain('Lateral Movement')
  })

  it('renders total alerts count', async () => {
    const w = shallowMount(AlertsView)
    await flushPromises()
    expect(w.text()).toContain('2')
  })

  it('renders endpoint names from agentRealtimeInfo', async () => {
    const w = shallowMount(AlertsView)
    await flushPromises()
    expect(w.text()).toContain('WS-FINANCE-01')
    expect(w.text()).toContain('DC-PRIMARY')
  })

  it('renders severity filter dropdown', async () => {
    const w = shallowMount(AlertsView)
    await flushPromises()
    const selects = w.findAll('select')
    expect(selects.length).toBeGreaterThanOrEqual(1)
    expect(w.find('[aria-label="Filter by severity"]').exists()).toBe(true)
  })

  it('renders search input', async () => {
    const w = shallowMount(AlertsView)
    await flushPromises()
    expect(w.find('[aria-label="Search alerts"]').exists()).toBe(true)
  })
})
