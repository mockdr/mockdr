import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useDashboardStore } from '../dashboard'

vi.mock('../../api/agents', () => ({ agentsApi: { list: vi.fn() } }))
vi.mock('../../api/threats', () => ({ threatsApi: { list: vi.fn() } }))
vi.mock('../../api/alerts', () => ({ alertsApi: { list: vi.fn() } }))
vi.mock('../../api/misc', () => ({
  activitiesApi: { list: vi.fn() },
  usersApi: { loginByToken: vi.fn() },
}))

import { agentsApi } from '../../api/agents'
import { threatsApi } from '../../api/threats'
import { alertsApi } from '../../api/alerts'
import { activitiesApi } from '../../api/misc'

function makeAgentsResponse(agents: object[]) {
  return { data: agents, pagination: { totalItems: agents.length, nextCursor: null } }
}
function makeThreatsResponse(threats: object[]) {
  return { data: threats, pagination: { totalItems: threats.length, nextCursor: null } }
}
function makeAlertsResponse(total: number) {
  return { data: [], pagination: { totalItems: total, nextCursor: null } }
}
function makeActivitiesResponse(activities: object[]) {
  return { data: activities, pagination: { totalItems: activities.length, nextCursor: null } }
}

const MOCK_AGENTS = [
  { id: 'a1', osType: 'windows', networkStatus: 'connected', infected: false, isActive: true },
  { id: 'a2', osType: 'macos',   networkStatus: 'connected', infected: true,  isActive: true },
  { id: 'a3', osType: 'linux',   networkStatus: 'disconnected', infected: false, isActive: false },
  { id: 'a4', osType: 'windows', networkStatus: 'disconnected', infected: false, isActive: true },
]

const MOCK_THREATS = [
  { id: 't1', threatInfo: { resolved: false }, agentDetectionInfo: {}, agentRealtimeInfo: {}, indicators: [], mitigationStatus: [], whiteningOptions: [] },
  { id: 't2', threatInfo: { resolved: true  }, agentDetectionInfo: {}, agentRealtimeInfo: {}, indicators: [], mitigationStatus: [], whiteningOptions: [] },
]

const MOCK_ACTIVITIES = [
  { id: 'act1', description: 'Agent connected', createdAt: '2024-01-01T00:00:00.000Z' },
]

describe('useDashboardStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
    vi.mocked(agentsApi.list).mockResolvedValue(makeAgentsResponse(MOCK_AGENTS) as never)
    vi.mocked(threatsApi.list).mockResolvedValue(makeThreatsResponse(MOCK_THREATS) as never)
    vi.mocked(alertsApi.list).mockResolvedValue(makeAlertsResponse(7) as never)
    vi.mocked(activitiesApi.list).mockResolvedValue(makeActivitiesResponse(MOCK_ACTIVITIES) as never)
  })

  describe('initial state', () => {
    it('summary starts at zero counts', () => {
      const store = useDashboardStore()
      expect(store.summary.totalAgents).toBe(0)
      expect(store.summary.activeThreats).toBe(0)
      expect(store.summary.unresolvedAlerts).toBe(0)
    })

    it('loading is false initially', () => {
      expect(useDashboardStore().loading).toBe(false)
    })
  })

  describe('fetchAll()', () => {
    it('populates totalAgents from pagination', async () => {
      const store = useDashboardStore()
      await store.fetchAll()
      expect(store.summary.totalAgents).toBe(4)
    })

    it('counts active threats (resolved=false)', async () => {
      const store = useDashboardStore()
      await store.fetchAll()
      expect(store.summary.activeThreats).toBe(1) // only t1 is not resolved
    })

    it('populates unresolvedAlerts from alerts pagination.totalItems', async () => {
      const store = useDashboardStore()
      await store.fetchAll()
      expect(store.summary.unresolvedAlerts).toBe(7)
    })

    it('counts offline agents (networkStatus=disconnected)', async () => {
      const store = useDashboardStore()
      await store.fetchAll()
      expect(store.summary.offlineAgents).toBe(2) // a3, a4
    })

    it('counts infected agents', async () => {
      const store = useDashboardStore()
      await store.fetchAll()
      expect(store.summary.infectedAgents).toBe(1) // a2
    })

    it('populates agentsByOs breakdown', async () => {
      const store = useDashboardStore()
      await store.fetchAll()
      expect(store.agentsByOs.windows).toBe(2)
      expect(store.agentsByOs.macos).toBe(1)
      expect(store.agentsByOs.linux).toBe(1)
    })

    it('populates agentsByStatus breakdown', async () => {
      const store = useDashboardStore()
      await store.fetchAll()
      expect(store.agentsByStatus.connected).toBe(2)
      expect(store.agentsByStatus.disconnected).toBe(2)
      expect(store.agentsByStatus.inactive).toBe(1) // a3 isActive=false
    })

    it('populates recentThreats (up to 5)', async () => {
      const store = useDashboardStore()
      await store.fetchAll()
      expect(store.recentThreats).toHaveLength(2)
    })

    it('populates recentActivities', async () => {
      const store = useDashboardStore()
      await store.fetchAll()
      expect(store.recentActivities).toHaveLength(1)
      expect(store.recentActivities[0].id).toBe('act1')
    })

    it('sets loading=false after success', async () => {
      const store = useDashboardStore()
      await store.fetchAll()
      expect(store.loading).toBe(false)
    })

    it('sets loading=false even when one API call rejects', async () => {
      vi.mocked(agentsApi.list).mockRejectedValueOnce(new Error('network'))
      const store = useDashboardStore()
      await store.fetchAll().catch(() => undefined)
      expect(store.loading).toBe(false)
    })

    it('calls all four API endpoints in one fetchAll', async () => {
      const store = useDashboardStore()
      await store.fetchAll()
      expect(agentsApi.list).toHaveBeenCalledOnce()
      expect(threatsApi.list).toHaveBeenCalledOnce()
      expect(alertsApi.list).toHaveBeenCalledOnce()
      expect(activitiesApi.list).toHaveBeenCalledOnce()
    })
  })
})
