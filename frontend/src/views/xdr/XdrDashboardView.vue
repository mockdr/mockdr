<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { AlertTriangle, ShieldAlert, Monitor, RefreshCw } from 'lucide-vue-next'
import { Doughnut } from 'vue-chartjs'
import {
  Chart as ChartJS, ArcElement, Tooltip, Legend,
} from 'chart.js'
import { xdrIncidentsApi, xdrAlertsApi, xdrEndpointsApi } from '../../api/cortex'
import type { XdrIncident, XdrAlert, XdrEndpoint } from '../../types/cortex'
import { formatEpoch } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

ChartJS.register(ArcElement, Tooltip, Legend)

const loading = ref(true)
const error = ref('')

const incidentCount = ref(0)
const alertCount = ref(0)
const endpointCount = ref(0)

const incidents = ref<XdrIncident[]>([])
const alerts = ref<XdrAlert[]>([])
const endpoints = ref<XdrEndpoint[]>([])

let timer: ReturnType<typeof setInterval>

const summaryCards = computed(() => [
  { label: 'Incidents', value: incidentCount.value, icon: AlertTriangle, color: 'text-orange-400', bg: 'bg-orange-500/10' },
  { label: 'Alerts', value: alertCount.value, icon: ShieldAlert, color: 'text-red-400', bg: 'bg-red-500/10' },
  { label: 'Endpoints', value: endpointCount.value, icon: Monitor, color: 'text-cyan-400', bg: 'bg-cyan-500/10' },
])

const severityChartData = computed(() => {
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const inc of incidents.value) {
    const sev = (inc.severity ?? 'low').toLowerCase()
    counts[sev] = (counts[sev] ?? 0) + 1
  }
  return {
    labels: Object.keys(counts).filter(k => counts[k] > 0),
    datasets: [{
      data: Object.keys(counts).filter(k => counts[k] > 0).map(k => counts[k]),
      backgroundColor: ['#EF4444', '#F97316', '#EAB308', '#3B82F6'],
      borderWidth: 0,
    }],
  }
})

const alertSourceChartData = computed(() => {
  const counts: Record<string, number> = {}
  for (const a of alerts.value) {
    const key = a.source ?? 'Unknown'
    counts[key] = (counts[key] ?? 0) + 1
  }
  return {
    labels: Object.keys(counts),
    datasets: [{
      data: Object.values(counts),
      backgroundColor: ['#F97316', '#3B82F6', '#A855F7', '#22C55E', '#6B7280'],
      borderWidth: 0,
    }],
  }
})

const endpointOsChartData = computed(() => {
  const counts: Record<string, number> = {}
  for (const ep of endpoints.value) {
    const key = ep.os_type ?? 'Unknown'
    counts[key] = (counts[key] ?? 0) + 1
  }
  return {
    labels: Object.keys(counts),
    datasets: [{
      data: Object.values(counts),
      backgroundColor: ['#3B82F6', '#22C55E', '#A855F7', '#6B7280'],
      borderWidth: 0,
    }],
  }
})

const chartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      position: 'bottom' as const,
      labels: { color: '#94A3B8', font: { size: 11 }, padding: 12 },
    },
  },
}


function severityBadgeClass(severity: string): string {
  switch ((severity ?? '').toLowerCase()) {
    case 'critical': return 'bg-red-500/15 text-red-400'
    case 'high': return 'bg-orange-500/15 text-orange-400'
    case 'medium': return 'bg-yellow-500/15 text-yellow-400'
    case 'low': return 'bg-blue-500/15 text-blue-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function fetchAll(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const [incRes, alertRes, epRes] = await Promise.all([
      xdrIncidentsApi.list(),
      xdrAlertsApi.list(),
      xdrEndpointsApi.list(),
    ])

    incidents.value = incRes.reply?.incidents ?? []
    incidentCount.value = incRes.reply?.total_count ?? incidents.value.length

    alerts.value = alertRes.reply?.alerts ?? []
    alertCount.value = alertRes.reply?.total_count ?? alerts.value.length

    endpoints.value = epRes.reply?.endpoints ?? []
    endpointCount.value = epRes.reply?.total_count ?? endpoints.value.length
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
          <span class="text-orange-500 font-bold">XDR</span> Cortex XDR Dashboard
        </h1>
        <p class="text-s1-muted text-sm">Palo Alto Cortex XDR overview</p>
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
    <div class="grid grid-cols-3 gap-4">
      <div
        v-for="card in summaryCards" :key="card.label"
        class="card p-5 border-l-2 border-l-orange-500/50"
      >
        <div class="flex items-start justify-between">
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

    <!-- Charts row -->
    <div class="grid grid-cols-3 gap-4">
      <div class="card p-5">
        <h3 class="text-sm font-semibold text-s1-text mb-4">Incident Severity</h3>
        <div class="h-40">
          <Doughnut v-if="!loading && incidents.length" :data="severityChartData" :options="chartOptions" />
          <div v-else-if="!loading" class="flex items-center justify-center h-full text-s1-muted text-sm">No data</div>
          <LoadingSkeleton v-else :rows="3" />
        </div>
      </div>

      <div class="card p-5">
        <h3 class="text-sm font-semibold text-s1-text mb-4">Alert Source</h3>
        <div class="h-40">
          <Doughnut v-if="!loading && alerts.length" :data="alertSourceChartData" :options="chartOptions" />
          <div v-else-if="!loading" class="flex items-center justify-center h-full text-s1-muted text-sm">No data</div>
          <LoadingSkeleton v-else :rows="3" />
        </div>
      </div>

      <div class="card p-5">
        <h3 class="text-sm font-semibold text-s1-text mb-4">Endpoint OS</h3>
        <div class="h-40">
          <Doughnut v-if="!loading && endpoints.length" :data="endpointOsChartData" :options="chartOptions" />
          <div v-else-if="!loading" class="flex items-center justify-center h-full text-s1-muted text-sm">No data</div>
          <LoadingSkeleton v-else :rows="3" />
        </div>
      </div>
    </div>

    <!-- Tables row -->
    <div class="grid grid-cols-2 gap-4">
      <!-- Recent Incidents -->
      <div class="card">
        <div class="flex items-center justify-between px-5 py-4 border-b border-s1-border">
          <h3 class="text-sm font-semibold text-s1-text">Recent Incidents</h3>
          <RouterLink to="/cortex-xdr/incidents" class="text-xs text-orange-400 hover:underline">View all</RouterLink>
        </div>
        <LoadingSkeleton v-if="loading" :rows="5" />
        <div v-else class="divide-y divide-s1-border">
          <RouterLink
            v-for="inc in incidents.slice(0, 5)" :key="inc.incident_id"
            :to="`/cortex-xdr/incidents/${inc.incident_id}`"
            class="block px-5 py-3 hover:bg-s1-hover transition-colors cursor-pointer"
          >
            <div class="flex items-center justify-between">
              <div class="text-sm text-s1-text truncate max-w-[70%]">{{ inc.description || `Incident ${inc.incident_id}` }}</div>
              <span
                class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                :class="severityBadgeClass(inc.severity)"
              >
                {{ inc.severity }}
              </span>
            </div>
            <div class="text-xs text-s1-muted mt-0.5">{{ inc.status }} | {{ inc.alert_count }} alerts | {{ formatEpoch(inc.creation_time) }}</div>
          </RouterLink>
        </div>
        <div v-if="!loading && !incidents.length" class="py-8 text-center text-s1-muted text-sm">
          No recent incidents
        </div>
      </div>

      <!-- Recent Alerts -->
      <div class="card">
        <div class="flex items-center justify-between px-5 py-4 border-b border-s1-border">
          <h3 class="text-sm font-semibold text-s1-text">Recent Alerts</h3>
          <RouterLink to="/cortex-xdr/alerts" class="text-xs text-orange-400 hover:underline">View all</RouterLink>
        </div>
        <LoadingSkeleton v-if="loading" :rows="5" />
        <div v-else class="divide-y divide-s1-border">
          <div
            v-for="alert in alerts.slice(0, 5)" :key="alert.alert_id"
            class="px-5 py-3 hover:bg-s1-hover transition-colors cursor-pointer"
          >
            <div class="flex items-center justify-between">
              <div class="text-sm text-s1-text truncate max-w-[70%]">{{ alert.name }}</div>
              <span
                class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                :class="severityBadgeClass(alert.severity)"
              >
                {{ alert.severity }}
              </span>
            </div>
            <div class="text-xs text-s1-muted mt-0.5">{{ alert.source }} | {{ alert.host_name }} | {{ formatEpoch(alert.detection_timestamp) }}</div>
          </div>
        </div>
        <div v-if="!loading && !alerts.length" class="py-8 text-center text-s1-muted text-sm">
          No recent alerts
        </div>
      </div>
    </div>
  </div>
</template>
