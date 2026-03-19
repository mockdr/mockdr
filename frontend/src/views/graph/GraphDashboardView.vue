<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { Users, Monitor, ShieldAlert, CheckCircle, RefreshCw } from 'lucide-vue-next'
import { ensureGraphAuth, graphUsersApi, graphDevicesApi, graphSecurityApi } from '../../api/graph'
import type { GraphUser, GraphManagedDevice, GraphSecurityIncident } from '../../types/graph'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

const loading = ref(true)
const error = ref('')

const userCount = ref(0)
const deviceCount = ref(0)
const openIncidentCount = ref(0)
const complianceRate = ref(0)

let timer: ReturnType<typeof setInterval>

const summaryCards = computed(() => [
  { label: 'Users', value: userCount.value, icon: Users, color: 'text-blue-400', bg: 'bg-blue-500/10' },
  { label: 'Managed Devices', value: deviceCount.value, icon: Monitor, color: 'text-sky-400', bg: 'bg-sky-500/10' },
  { label: 'Open Incidents', value: openIncidentCount.value, icon: ShieldAlert, color: 'text-red-400', bg: 'bg-red-500/10' },
  { label: 'Compliance Rate', value: `${complianceRate.value}%`, icon: CheckCircle, color: 'text-emerald-400', bg: 'bg-emerald-500/10' },
])

async function fetchAll(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    await ensureGraphAuth()

    const [usersRes, devicesRes, incidentsRes] = await Promise.all([
      graphUsersApi.list({ $top: 999 }),
      graphDevicesApi.list({ $top: 999 }),
      graphSecurityApi.listIncidents({ $top: 999 }),
    ])

    const users: GraphUser[] = usersRes.value ?? []
    const devices: GraphManagedDevice[] = devicesRes.value ?? []
    const incidents: GraphSecurityIncident[] = incidentsRes.value ?? []

    userCount.value = users.length
    deviceCount.value = devices.length
    openIncidentCount.value = incidents.filter(
      (i) => i.status !== 'resolved' && i.status !== 'redirected',
    ).length

    const compliant = devices.filter((d) => d.complianceState === 'compliant').length
    complianceRate.value = devices.length > 0
      ? Math.round((compliant / devices.length) * 100)
      : 0
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : 'Failed to fetch data'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  fetchAll()
  timer = setInterval(fetchAll, 30000)
})

onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="font-bold" style="color: #0078D4">Graph</span> Dashboard
        </h1>
        <p class="text-s1-muted text-sm">Microsoft Graph API overview</p>
      </div>
      <button @click="fetchAll()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Error banner -->
    <div v-if="error" class="card p-4 border-red-500/40 bg-red-500/10 text-red-400 text-sm">
      {{ error }}
    </div>

    <!-- Summary cards -->
    <div class="grid grid-cols-4 gap-4">
      <div
        v-for="card in summaryCards" :key="card.label"
        class="card p-5" style="border-left: 2px solid rgba(0, 120, 212, 0.5)"
      >
        <LoadingSkeleton v-if="loading" :rows="2" />
        <div v-else class="flex items-start justify-between">
          <div>
            <div class="text-3xl font-bold text-s1-text">{{ card.value }}</div>
            <div class="text-sm text-s1-muted mt-1">{{ card.label }}</div>
          </div>
          <div class="p-2.5 rounded-xl" :class="card.bg">
            <component :is="card.icon" class="w-5 h-5" :class="card.color" />
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
