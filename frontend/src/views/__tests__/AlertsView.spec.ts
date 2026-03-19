import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import AlertsView from '@/views/AlertsView.vue'

const mockAlertsList = vi.hoisted(() => vi.fn())

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('@vueuse/core', () => ({
  useDebounce: vi.fn((ref) => ref),
}))

vi.mock('../../api/alerts', () => ({
  alertsApi: { list: mockAlertsList },
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

const stubs = { StatusBadge: true, LoadingSkeleton: true, EmptyState: true }

describe('AlertsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockAlertsList.mockResolvedValue({
      data: FAKE_ALERTS,
      pagination: { totalItems: 2, nextCursor: null },
    })
  })

  it('renders the Alerts heading', async () => {
    const w = mount(AlertsView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('Alerts')
  })

  it('calls alertsApi.list on mount', async () => {
    mount(AlertsView, { global: { stubs } })
    await flushPromises()
    expect(mockAlertsList).toHaveBeenCalledOnce()
  })

  it('renders alert rule names after load', async () => {
    const w = mount(AlertsView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('Suspicious PowerShell')
    expect(w.text()).toContain('Lateral Movement')
  })

  it('renders total alerts count', async () => {
    const w = mount(AlertsView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('2')
  })

  it('renders endpoint names from agentRealtimeInfo', async () => {
    const w = mount(AlertsView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('WS-FINANCE-01')
    expect(w.text()).toContain('DC-PRIMARY')
  })

  it('renders severity filter dropdown', async () => {
    const w = mount(AlertsView, { global: { stubs } })
    await flushPromises()
    expect(w.find('[aria-label="Filter by severity"]').exists()).toBe(true)
  })

  it('renders search input', async () => {
    const w = mount(AlertsView, { global: { stubs } })
    await flushPromises()
    expect(w.find('[aria-label="Search alerts"]').exists()).toBe(true)
  })

  it('fetchList with reset=true replaces items', async () => {
    const w = mount(AlertsView, { global: { stubs } })
    await flushPromises()
    mockAlertsList.mockResolvedValue({
      data: [FAKE_ALERTS[0]],
      pagination: { totalItems: 1, nextCursor: null },
    })
    await (w.vm as any).fetchList(true)
    await flushPromises()
    expect((w.vm as any).items).toHaveLength(1)
  })

  it('fetchList with reset=false appends items', async () => {
    const w = mount(AlertsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).items = [FAKE_ALERTS[0]]
    mockAlertsList.mockResolvedValue({
      data: [FAKE_ALERTS[1]],
      pagination: { totalItems: 2, nextCursor: null },
    })
    await (w.vm as any).fetchList(false)
    await flushPromises()
    expect((w.vm as any).items).toHaveLength(2)
  })

  it('fetchList passes cursor when nextCursor is set', async () => {
    const w = mount(AlertsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).nextCursor = 'cursor-abc'
    await (w.vm as any).fetchList(false)
    await flushPromises()
    expect(mockAlertsList).toHaveBeenCalledWith(expect.objectContaining({ cursor: 'cursor-abc' }))
  })

  it('fetchList passes query param when query is set', async () => {
    const w = mount(AlertsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).query = 'malware'
    await (w.vm as any).fetchList()
    await flushPromises()
    expect(mockAlertsList).toHaveBeenCalledWith(expect.objectContaining({ query: 'malware' }))
  })

  it('fetchList passes severities when severity filter set', async () => {
    const w = mount(AlertsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).severity = 'Critical'
    await (w.vm as any).fetchList()
    await flushPromises()
    expect(mockAlertsList).toHaveBeenCalledWith(expect.objectContaining({ severities: 'Critical' }))
  })

  it('fetchList passes incidentStatuses when incidentStatus filter set', async () => {
    const w = mount(AlertsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).incidentStatus = 'Unresolved'
    await (w.vm as any).fetchList()
    await flushPromises()
    expect(mockAlertsList).toHaveBeenCalledWith(expect.objectContaining({ incidentStatuses: 'Unresolved' }))
  })

  it('sets loading to false after fetchList completes', async () => {
    const w = mount(AlertsView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).loading).toBe(false)
  })

  it('shows load more button when nextCursor is set', async () => {
    mockAlertsList.mockResolvedValue({
      data: FAKE_ALERTS,
      pagination: { totalItems: 5, nextCursor: 'next-page' },
    })
    const w = mount(AlertsView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('Load more')
  })

  it('SEVERITY_COLOR contains High', () => {
    const w = mount(AlertsView, { global: { stubs } })
    expect((w.vm as any).SEVERITY_COLOR['High']).toBeTruthy()
  })

  it('SEVERITY_COLOR contains Critical', () => {
    const w = mount(AlertsView, { global: { stubs } })
    expect((w.vm as any).SEVERITY_COLOR['Critical']).toBeTruthy()
  })

  it('severity select @change calls fetchList via DOM', async () => {
    const w = mount(AlertsView, { global: { stubs } })
    await flushPromises()
    mockAlertsList.mockClear()
    const sel = w.find('[aria-label="Filter by severity"]')
    await sel.trigger('change')
    await flushPromises()
    expect(mockAlertsList).toHaveBeenCalled()
  })

  it('status select @change calls fetchList via DOM', async () => {
    const w = mount(AlertsView, { global: { stubs } })
    await flushPromises()
    mockAlertsList.mockClear()
    const sel = w.find('[aria-label="Filter by status"]')
    await sel.trigger('change')
    await flushPromises()
    expect(mockAlertsList).toHaveBeenCalled()
  })

  it('Load more button calls fetchList(false) via DOM', async () => {
    mockAlertsList.mockResolvedValue({
      data: FAKE_ALERTS,
      pagination: { totalItems: 5, nextCursor: 'next-page' },
    })
    const w = mount(AlertsView, { global: { stubs } })
    await flushPromises()
    mockAlertsList.mockClear()
    const loadMoreBtn = w.find('button')
    await loadMoreBtn.trigger('click')
    await flushPromises()
    expect(mockAlertsList).toHaveBeenCalled()
  })
})
