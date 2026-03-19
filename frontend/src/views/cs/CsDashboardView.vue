<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { Monitor, ShieldAlert, AlertTriangle, RefreshCw } from 'lucide-vue-next'
import { Doughnut } from 'vue-chartjs'
import {
  Chart as ChartJS, ArcElement, Tooltip, Legend,
} from 'chart.js'
import { ensureCsAuth, csHostsApi, csDetectionsApi, csIncidentsApi } from '../../api/crowdstrike'
import type { CsHost, CsDetection, CsIncident } from '../../types/crowdstrike'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

ChartJS.register(ArcElement, Tooltip, Legend)

const router = useRouter()
const loading = ref(true)
const error = ref('')

// Summary counts
const hostCount = ref(0)
const detectionCount = ref(0)
const incidentCount = ref(0)

// Entities for charts
const hosts = ref<CsHost[]>([])
const detections = ref<CsDetection[]>([])
const incidents = ref<CsIncident[]>([])

let timer: ReturnType<typeof setInterval>

const summaryCards = computed(() => [
  { label: 'Total Hosts', value: hostCount.value, icon: Monitor, color: 'text-red-400', bg: 'bg-red-500/10' },
  { label: 'Detections', value: detectionCount.value, icon: ShieldAlert, color: 'text-orange-400', bg: 'bg-orange-500/10' },
  { label: 'Incidents', value: incidentCount.value, icon: AlertTriangle, color: 'text-yellow-400', bg: 'bg-yellow-500/10' },
])

// Platform distribution chart
const platformChartData = computed(() => {
  const counts: Record<string, number> = { Windows: 0, Mac: 0, Linux: 0 }
  for (const h of hosts.value) {
    const key = h.platform_name ?? 'Unknown'
    counts[key] = (counts[key] ?? 0) + 1
  }
  return {
    labels: Object.keys(counts),
    datasets: [{
      data: Object.values(counts),
      backgroundColor: ['#EF4444', '#F97316', '#EAB308'],
      borderWidth: 0,
    }],
  }
})

// Detection severity distribution chart
const severityChartData = computed(() => {
  const counts: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 }
  for (const d of detections.value) {
    const sev = d.max_severity_displayname ?? 'Unknown'
    counts[sev] = (counts[sev] ?? 0) + 1
  }
  return {
    labels: Object.keys(counts).filter(k => counts[k] > 0),
    datasets: [{
      data: Object.keys(counts).filter(k => counts[k] > 0).map(k => counts[k]),
      backgroundColor: ['#EF4444', '#F97316', '#EAB308', '#3B82F6', '#6B7280'],
      borderWidth: 0,
    }],
  }
})

// Incident status distribution chart
const incidentStatusChartData = computed(() => {
  const STATUS_MAP: Record<number, string> = { 20: 'New', 25: 'Reopened', 30: 'In Progress', 40: 'Closed' }
  const counts: Record<string, number> = {}
  for (const inc of incidents.value) {
    const label = STATUS_MAP[inc.status] ?? `Status ${inc.status}`
    counts[label] = (counts[label] ?? 0) + 1
  }
  return {
    labels: Object.keys(counts),
    datasets: [{
      data: Object.values(counts),
      backgroundColor: ['#3B82F6', '#F97316', '#EAB308', '#22C55E'],
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

async function fetchAll(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    await ensureCsAuth()

    const [hostIdsRes, detIdsRes, incIdsRes] = await Promise.all([
      csHostsApi.queryIds({ limit: 100 }),
      csDetectionsApi.queryIds({ limit: 100 }),
      csIncidentsApi.queryIds({ limit: 100 }),
    ])

    hostCount.value = hostIdsRes.meta.pagination?.total ?? hostIdsRes.resources.length
    detectionCount.value = detIdsRes.meta.pagination?.total ?? detIdsRes.resources.length
    incidentCount.value = incIdsRes.meta.pagination?.total ?? incIdsRes.resources.length

    // Fetch sample entities for charts
    const [hostsRes, detsRes, incsRes] = await Promise.all([
      hostIdsRes.resources.length > 0
        ? csHostsApi.getEntities(hostIdsRes.resources.slice(0, 50))
        : Promise.resolve({ resources: [] as CsHost[], meta: { query_time: 0, powered_by: '', trace_id: '' }, errors: [] }),
      detIdsRes.resources.length > 0
        ? csDetectionsApi.getEntities(detIdsRes.resources.slice(0, 50))
        : Promise.resolve({ resources: [] as CsDetection[], meta: { query_time: 0, powered_by: '', trace_id: '' }, errors: [] }),
      incIdsRes.resources.length > 0
        ? csIncidentsApi.getEntities(incIdsRes.resources.slice(0, 50))
        : Promise.resolve({ resources: [] as CsIncident[], meta: { query_time: 0, powered_by: '', trace_id: '' }, errors: [] }),
    ])

    hosts.value = hostsRes.resources
    detections.value = detsRes.resources
    incidents.value = incsRes.resources
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
          <span class="text-red-500 font-bold">CS</span> CrowdStrike Dashboard
        </h1>
        <p class="text-s1-muted text-sm">Falcon host and detection overview</p>
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
        class="card p-5 border-l-2 border-l-red-500/50"
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
      <!-- Platform Distribution -->
      <div class="card p-5">
        <h3 class="text-sm font-semibold text-s1-text mb-4">Platform Distribution</h3>
        <div class="h-40">
          <Doughnut v-if="!loading && hosts.length" :data="platformChartData" :options="chartOptions" />
          <div v-else-if="!loading" class="flex items-center justify-center h-full text-s1-muted text-sm">No data</div>
          <LoadingSkeleton v-else :rows="3" />
        </div>
      </div>

      <!-- Detection Severity -->
      <div class="card p-5">
        <h3 class="text-sm font-semibold text-s1-text mb-4">Detection Severity</h3>
        <div class="h-40">
          <Doughnut v-if="!loading && detections.length" :data="severityChartData" :options="chartOptions" />
          <div v-else-if="!loading" class="flex items-center justify-center h-full text-s1-muted text-sm">No data</div>
          <LoadingSkeleton v-else :rows="3" />
        </div>
      </div>

      <!-- Incident Status -->
      <div class="card p-5">
        <h3 class="text-sm font-semibold text-s1-text mb-4">Incident Status</h3>
        <div class="h-40">
          <Doughnut v-if="!loading && incidents.length" :data="incidentStatusChartData" :options="chartOptions" />
          <div v-else-if="!loading" class="flex items-center justify-center h-full text-s1-muted text-sm">No data</div>
          <LoadingSkeleton v-else :rows="3" />
        </div>
      </div>
    </div>

    <!-- Tables row -->
    <div class="grid grid-cols-2 gap-4">
      <!-- Recent Detections -->
      <div class="card">
        <div class="flex items-center justify-between px-5 py-4 border-b border-s1-border">
          <h3 class="text-sm font-semibold text-s1-text">Recent Detections</h3>
          <RouterLink to="/crowdstrike/detections" class="text-xs text-red-400 hover:underline">View all</RouterLink>
        </div>
        <LoadingSkeleton v-if="loading" :rows="5" />
        <table v-else class="w-full">
          <tbody>
            <tr
              v-for="det in detections.slice(0, 5)" :key="det.composite_id"
              class="table-row"
              @click="router.push(`/crowdstrike/detections/${det.composite_id}`)"
            >
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm truncate max-w-[160px]">
                  {{ det.device?.hostname ?? 'Unknown' }}
                </div>
                <div class="text-xs text-s1-muted">{{ det.behaviors?.[0]?.scenario ?? '—' }}</div>
              </td>
              <td class="table-cell">
                <span
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="{
                    'bg-red-500/15 text-red-400': det.max_severity >= 80,
                    'bg-orange-500/15 text-orange-400': det.max_severity >= 60 && det.max_severity < 80,
                    'bg-yellow-500/15 text-yellow-400': det.max_severity >= 40 && det.max_severity < 60,
                    'bg-blue-500/15 text-blue-400': det.max_severity >= 20 && det.max_severity < 40,
                    'bg-gray-500/15 text-gray-400': det.max_severity < 20,
                  }"
                >
                  {{ det.max_severity_displayname }}
                </span>
              </td>
              <td class="table-cell text-xs text-s1-muted">{{ det.status }}</td>
            </tr>
          </tbody>
        </table>
        <div v-if="!loading && !detections.length" class="py-8 text-center text-s1-muted text-sm">
          No recent detections
        </div>
      </div>

      <!-- Recent Incidents -->
      <div class="card">
        <div class="flex items-center justify-between px-5 py-4 border-b border-s1-border">
          <h3 class="text-sm font-semibold text-s1-text">Recent Incidents</h3>
          <RouterLink to="/crowdstrike/incidents" class="text-xs text-red-400 hover:underline">View all</RouterLink>
        </div>
        <LoadingSkeleton v-if="loading" :rows="5" />
        <div v-else class="divide-y divide-s1-border">
          <div
            v-for="inc in incidents.slice(0, 5)" :key="inc.incident_id"
            class="px-5 py-3 hover:bg-s1-hover transition-colors cursor-pointer"
            @click="router.push('/crowdstrike/incidents')"
          >
            <div class="flex items-center justify-between">
              <div class="text-sm text-s1-text truncate max-w-[70%]">{{ inc.name }}</div>
              <span
                class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                :class="{
                  'bg-blue-500/15 text-blue-400': inc.status === 20,
                  'bg-orange-500/15 text-orange-400': inc.status === 25,
                  'bg-yellow-500/15 text-yellow-400': inc.status === 30,
                  'bg-green-500/15 text-green-400': inc.status === 40,
                }"
              >
                {{ { 20: 'New', 25: 'Reopened', 30: 'In Progress', 40: 'Closed' }[inc.status] ?? inc.status }}
              </span>
            </div>
            <div class="text-xs text-s1-muted mt-0.5">
              Score: {{ inc.fine_score }} | {{ inc.hosts?.length ?? 0 }} host(s)
            </div>
          </div>
        </div>
        <div v-if="!loading && !incidents.length" class="py-8 text-center text-s1-muted text-sm">
          No incidents
        </div>
      </div>
    </div>
  </div>
</template>
