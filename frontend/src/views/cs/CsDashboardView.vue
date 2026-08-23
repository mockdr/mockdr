<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { Monitor, ShieldAlert, RefreshCw } from 'lucide-vue-next'
import { Doughnut } from 'vue-chartjs'
import {
  Chart as ChartJS, ArcElement, Tooltip, Legend,
} from 'chart.js'
import { ensureCsAuth, csHostsApi, csDetectionsApi } from '../../api/crowdstrike'
import type { CsHost, CsDetection } from '../../types/crowdstrike'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

ChartJS.register(ArcElement, Tooltip, Legend)

const loading = ref(true)
const error = ref('')

// Summary counts
const hostCount = ref(0)
const detectionCount = ref(0)

// Entities for charts
const hosts = ref<CsHost[]>([])
const detections = ref<CsDetection[]>([])

let timer: ReturnType<typeof setInterval>

const summaryCards = computed(() => [
  { label: 'Total Hosts', value: hostCount.value, icon: Monitor, color: 'text-red-400', bg: 'bg-red-500/10' },
  { label: 'Detections', value: detectionCount.value, icon: ShieldAlert, color: 'text-orange-400', bg: 'bg-orange-500/10' },
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

    const [hostIdsRes, detIdsRes] = await Promise.all([
      csHostsApi.queryIds({ limit: 100 }),
      csDetectionsApi.queryIds({ limit: 100 }),
    ])

    hostCount.value = hostIdsRes.meta.pagination?.total ?? hostIdsRes.resources.length
    detectionCount.value = detIdsRes.meta.pagination?.total ?? detIdsRes.resources.length

    // Fetch sample entities for charts
    const [hostsRes, detsRes] = await Promise.all([
      hostIdsRes.resources.length > 0
        ? csHostsApi.getEntities(hostIdsRes.resources.slice(0, 50))
        : Promise.resolve({ resources: [] as CsHost[], meta: { query_time: 0, powered_by: '', trace_id: '' }, errors: [] }),
      detIdsRes.resources.length > 0
        ? csDetectionsApi.getEntities(detIdsRes.resources.slice(0, 50))
        : Promise.resolve({ resources: [] as CsDetection[], meta: { query_time: 0, powered_by: '', trace_id: '' }, errors: [] }),
    ])

    hosts.value = hostsRes.resources
    detections.value = detsRes.resources
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
          <Doughnut v-if="!loading && hosts.length" :data="platformChartData" :options="chartOptions" aria-label="Platform Distribution" />
          <div v-else-if="!loading" class="flex items-center justify-center h-full text-s1-muted text-sm">No data</div>
          <LoadingSkeleton v-else :rows="3" />
        </div>
      </div>

      <!-- Detection Severity -->
      <div class="card p-5">
        <h3 class="text-sm font-semibold text-s1-text mb-4">Detection Severity</h3>
        <div class="h-40">
          <Doughnut v-if="!loading && detections.length" :data="severityChartData" :options="chartOptions" aria-label="Detection Severity" />
          <div v-else-if="!loading" class="flex items-center justify-center h-full text-s1-muted text-sm">No data</div>
          <LoadingSkeleton v-else :rows="3" />
        </div>
      </div>


    </div>
  </div>
</template>
