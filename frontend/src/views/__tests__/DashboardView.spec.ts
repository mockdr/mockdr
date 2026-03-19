import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { shallowMount } from '@vue/test-utils'
import DashboardView from '@/views/DashboardView.vue'

const mockFetchAll = vi.hoisted(() => vi.fn())

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('vue-chartjs', () => ({
  Doughnut: { template: '<canvas />' },
}))

vi.mock('chart.js', () => ({
  Chart: { register: vi.fn() },
  ArcElement: {},
  Tooltip: {},
  Legend: {},
  CategoryScale: {},
  LinearScale: {},
  PointElement: {},
  LineElement: {},
  Filler: {},
}))

vi.mock('../../stores/dashboard', () => ({
  useDashboardStore: vi.fn(() => ({
    summary: {
      totalAgents: 150,
      activeThreats: 3,
      unresolvedAlerts: 7,
      offlineAgents: 12,
      infectedAgents: 2,
    },
    agentsByOs: { windows: 80, macos: 50, linux: 20 },
    agentsByStatus: { connected: 130, disconnected: 12, inactive: 8 },
    recentThreats: [
      {
        id: 't1',
        threatInfo: { threatName: 'Ransomware.Win32', mitigationStatus: 'active', classification: 'Malware' },
        agentDetectionInfo: { agentComputerName: 'WS-HR-03' },
      },
    ],
    recentActivities: [
      { id: 'act1', description: 'Agent connected', createdAt: '2025-06-01T10:00:00Z' },
    ],
    loading: false,
    fetchAll: mockFetchAll,
  })),
}))

describe('DashboardView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('renders without error', () => {
    const w = shallowMount(DashboardView)
    expect(w.exists()).toBe(true)
  })

  it('renders the Dashboard heading', () => {
    const w = shallowMount(DashboardView)
    expect(w.text()).toContain('Dashboard')
  })

  it('calls fetchAll on mount', () => {
    shallowMount(DashboardView)
    expect(mockFetchAll).toHaveBeenCalledOnce()
  })

  it('renders summary card values', () => {
    const w = shallowMount(DashboardView)
    expect(w.text()).toContain('150')
    expect(w.text()).toContain('Total Endpoints')
    expect(w.text()).toContain('3')
    expect(w.text()).toContain('Active Threats')
    expect(w.text()).toContain('7')
    expect(w.text()).toContain('Unresolved Alerts')
  })

  it('renders recent threat names', () => {
    const w = shallowMount(DashboardView)
    expect(w.text()).toContain('Ransomware.Win32')
  })

  it('renders recent activity descriptions', () => {
    const w = shallowMount(DashboardView)
    expect(w.text()).toContain('Agent connected')
  })

  it('renders Refresh button', () => {
    const w = shallowMount(DashboardView)
    expect(w.text()).toContain('Refresh')
  })
})
