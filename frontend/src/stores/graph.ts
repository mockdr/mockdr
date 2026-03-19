import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type {
  GraphUser,
  GraphManagedDevice,
  GraphSecurityAlert,
  GraphSecurityIncident,
  GraphGroup,
} from '../types/graph'
import {
  ensureGraphAuth,
  graphUsersApi,
  graphDevicesApi,
  graphSecurityApi,
  graphGroupsApi,
} from '../api/graph'

/**
 * Pinia store for Microsoft Graph API state.
 *
 * Manages users, devices, security alerts/incidents, and groups fetched from
 * the Graph mock API. Auto-authenticates before each fetch.
 */
export const useGraphStore = defineStore('graph', () => {
  // ── State ───────────────────────────────────────────────────────────────────

  const users = ref<GraphUser[]>([])
  const devices = ref<GraphManagedDevice[]>([])
  const alerts = ref<GraphSecurityAlert[]>([])
  const incidents = ref<GraphSecurityIncident[]>([])
  const groups = ref<GraphGroup[]>([])
  const loading = ref(false)
  const currentPlan = ref('plan2')

  // ── Actions ─────────────────────────────────────────────────────────────────

  /** Fetch all users from Microsoft Graph. */
  async function fetchUsers(): Promise<void> {
    loading.value = true
    try {
      await ensureGraphAuth()
      const res = await graphUsersApi.list()
      users.value = res.value
    } finally {
      loading.value = false
    }
  }

  /** Fetch all managed devices from Microsoft Graph. */
  async function fetchDevices(): Promise<void> {
    loading.value = true
    try {
      await ensureGraphAuth()
      const res = await graphDevicesApi.list()
      devices.value = res.value
    } finally {
      loading.value = false
    }
  }

  /** Fetch security alerts from Microsoft Graph. */
  async function fetchAlerts(): Promise<void> {
    loading.value = true
    try {
      await ensureGraphAuth()
      const res = await graphSecurityApi.listAlerts()
      alerts.value = res.value
    } finally {
      loading.value = false
    }
  }

  /** Fetch security incidents from Microsoft Graph. */
  async function fetchIncidents(): Promise<void> {
    loading.value = true
    try {
      await ensureGraphAuth()
      const res = await graphSecurityApi.listIncidents()
      incidents.value = res.value
    } finally {
      loading.value = false
    }
  }

  /** Fetch all groups from Microsoft Graph. */
  async function fetchGroups(): Promise<void> {
    loading.value = true
    try {
      await ensureGraphAuth()
      const res = await graphGroupsApi.list()
      groups.value = res.value
    } finally {
      loading.value = false
    }
  }

  // ── Computed ────────────────────────────────────────────────────────────────

  /** Percentage of managed devices that are compliant. */
  const complianceRate = computed<number>(() => {
    if (devices.value.length === 0) return 0
    const compliant = devices.value.filter((d) => d.complianceState === 'compliant').length
    return Math.round((compliant / devices.value.length) * 100)
  })

  /** MFA adoption rate (placeholder — will be computed from auth methods data). */
  const mfaAdoption = computed<number>(() => {
    // TODO: compute from authentication methods API data once available
    return 0
  })

  /** Alerts grouped by severity. */
  const alertsBySeverity = computed<Record<string, GraphSecurityAlert[]>>(() => {
    const grouped: Record<string, GraphSecurityAlert[]> = {}
    for (const alert of alerts.value) {
      const key = alert.severity ?? 'unknown'
      if (!grouped[key]) grouped[key] = []
      grouped[key].push(alert)
    }
    return grouped
  })

  return {
    // state
    users,
    devices,
    alerts,
    incidents,
    groups,
    loading,
    currentPlan,
    // actions
    fetchUsers,
    fetchDevices,
    fetchAlerts,
    fetchIncidents,
    fetchGroups,
    // computed
    complianceRate,
    mfaAdoption,
    alertsBySeverity,
  }
})
