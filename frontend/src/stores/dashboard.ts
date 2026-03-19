import { defineStore } from 'pinia'
import { ref } from 'vue'
import type { ThreatRecord, Activity } from '../types'
import { agentsApi } from '../api/agents'
import { threatsApi } from '../api/threats'
import { alertsApi } from '../api/alerts'
import { activitiesApi } from '../api/misc'

interface DashboardSummary {
  totalAgents: number
  activeThreats: number
  unresolvedAlerts: number
  offlineAgents: number
  infectedAgents: number
}

interface OsByOs {
  windows: number
  macos: number
  linux: number
}

interface AgentsByStatus {
  connected: number
  disconnected: number
  inactive: number
}

/**
 * Pinia store for dashboard aggregate data.
 *
 * Fetches summary counts, chart data, and recent items from multiple domains
 * in parallel on each call to fetchAll().
 */
export const useDashboardStore = defineStore('dashboard', () => {
  const summary = ref<DashboardSummary>({
    totalAgents: 0,
    activeThreats: 0,
    unresolvedAlerts: 0,
    offlineAgents: 0,
    infectedAgents: 0,
  })
  const recentThreats = ref<ThreatRecord[]>([])
  const recentActivities = ref<Activity[]>([])
  const agentsByOs = ref<OsByOs>({ windows: 0, macos: 0, linux: 0 })
  const agentsByStatus = ref<AgentsByStatus>({ connected: 0, disconnected: 0, inactive: 0 })
  const loading = ref<boolean>(false)
  const error = ref<string>('')

  /**
   * Fetch all dashboard data in parallel and populate reactive state.
   *
   * Agents and threats are fetched with a high limit to compute aggregates
   * client-side. Activities fetch the 10 most recent entries.
   */
  async function fetchAll(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const [agentsRes, threatsRes, alertsRes, activitiesRes] = await Promise.all([
        agentsApi.list({ limit: 200 }),
        threatsApi.list({ limit: 200 }),
        alertsApi.list({ incidentStatuses: 'unresolved', limit: 1 }),
        activitiesApi.list({ limit: 10 }),
      ])

      const agents = agentsRes.data
      const threats = threatsRes.data

      summary.value = {
        totalAgents: agentsRes.pagination.totalItems,
        activeThreats: threats.filter((t) => !t.threatInfo.resolved).length,
        unresolvedAlerts: alertsRes.pagination.totalItems,
        offlineAgents: agents.filter((a) => a.networkStatus === 'disconnected').length,
        infectedAgents: agents.filter((a) => a.infected).length,
      }

      agentsByOs.value = {
        windows: agents.filter((a) => a.osType === 'windows').length,
        macos:   agents.filter((a) => a.osType === 'macos').length,
        linux:   agents.filter((a) => a.osType === 'linux').length,
      }

      agentsByStatus.value = {
        connected:    agents.filter((a) => a.networkStatus === 'connected').length,
        disconnected: agents.filter((a) => a.networkStatus === 'disconnected').length,
        inactive:     agents.filter((a) => !a.isActive).length,
      }

      recentThreats.value = threats.slice(0, 5)
      recentActivities.value = activitiesRes.data.slice(0, 10)
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Failed to load dashboard data'
    } finally {
      loading.value = false
    }
  }

  return { summary, recentThreats, recentActivities, agentsByOs, agentsByStatus, loading, error, fetchAll }
})
