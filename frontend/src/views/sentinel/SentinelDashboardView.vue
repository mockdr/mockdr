<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { Shield, AlertTriangle, ShieldAlert, BookOpen, RefreshCw } from 'lucide-vue-next'
import { Doughnut, Bar } from 'vue-chartjs'
import {
  Chart as ChartJS, ArcElement, Tooltip, Legend,
  BarElement, CategoryScale, LinearScale,
} from 'chart.js'
import { sentinelIncidentApi } from '../../api/sentinel'
import type { ArmResource, SentinelIncidentProps } from '../../types/sentinel'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

ChartJS.register(ArcElement, Tooltip, Legend, BarElement, CategoryScale, LinearScale)

const loading = ref(true)
const error = ref('')

const incidents = ref<ArmResource<SentinelIncidentProps>[]>([])

let timer: ReturnType<typeof setInterval>

const openCount = computed(() =>
  incidents.value.filter(i => i.properties.status === 'New').length,
)
const activeCount = computed(() =>
  incidents.value.filter(i => i.properties.status === 'Active').length,
)
const closedCount = computed(() =>
  incidents.value.filter(i => i.properties.status === 'Closed').length,
)
const totalAlerts = computed(() =>
  incidents.value.reduce((sum, i) => sum + (i.properties.additionalData?.alertsCount ?? 0), 0),
)

const summaryCards = computed(() => [
  { label: 'Open Incidents', value: openCount.value, icon: AlertTriangle, color: 'text-red-400', bg: 'bg-red-500/10' },
  { label: 'Active Incidents', value: activeCount.value, icon: ShieldAlert, color: 'text-yellow-400', bg: 'bg-yellow-500/10' },
  { label: 'Closed Incidents', value: closedCount.value, icon: Shield, color: 'text-green-400', bg: 'bg-green-500/10' },
  { label: 'Total Alerts', value: totalAlerts.value, icon: BookOpen, color: 'text-blue-400', bg: 'bg-blue-500/10' },
])

const severityChartData = computed(() => {
  const counts: Record<string, number> = { High: 0, Medium: 0, Low: 0, Informational: 0 }
  for (const inc of incidents.value) {
    const sev = inc.properties.severity ?? 'Low'
    counts[sev] = (counts[sev] ?? 0) + 1
  }
  const labels = Object.keys(counts).filter(k => counts[k] > 0)
  return {
    labels,
    datasets: [{
      data: labels.map(k => counts[k]),
      backgroundColor: labels.map(k => {
        switch (k) {
          case 'High': return '#EF4444'
          case 'Medium': return '#F97316'
          case 'Low': return '#EAB308'
          case 'Informational': return '#3B82F6'
          default: return '#6B7280'
        }
      }),
      borderWidth: 0,
    }],
  }
})

const alertsByProductChartData = computed(() => {
  const counts: Record<string, number> = {}
  for (const inc of incidents.value) {
    const products = inc.properties.additionalData?.alertProductNames ?? []
    for (const product of products) {
      counts[product] = (counts[product] ?? 0) + 1
    }
  }
  const labels = Object.keys(counts)
  return {
    labels,
    datasets: [{
      data: labels.map(k => counts[k]),
      backgroundColor: ['#22C55E', '#3B82F6', '#A855F7', '#F97316', '#EF4444', '#6B7280'],
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

const barChartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: { legend: { display: false } },
  scales: {
    x: { ticks: { color: '#94A3B8' }, grid: { display: false } },
    y: { ticks: { color: '#94A3B8' }, grid: { color: '#1E293B' } },
  },
}

function severityBadgeClass(severity: string): string {
  switch ((severity ?? '').toLowerCase()) {
    case 'high': return 'bg-red-500/15 text-red-400'
    case 'medium': return 'bg-orange-500/15 text-orange-400'
    case 'low': return 'bg-yellow-500/15 text-yellow-400'
    case 'informational': return 'bg-blue-500/15 text-blue-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function fetchAll(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const res = await sentinelIncidentApi.list()
    incidents.value = res.value ?? []
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
          <Shield class="w-5 h-5 text-green-600" />
          <span class="text-green-600 font-bold">SNTL</span> Microsoft Sentinel Dashboard
        </h1>
        <p class="text-s1-muted text-sm">Microsoft Sentinel SIEM overview</p>
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
        class="card p-5 border-l-2 border-l-green-600/50"
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
    <div class="grid grid-cols-2 gap-4">
      <div class="card p-5">
        <h3 class="text-sm font-semibold text-s1-text mb-4">Incidents by Severity</h3>
        <div class="h-48">
          <Doughnut v-if="!loading && incidents.length" :data="severityChartData" :options="chartOptions" />
          <div v-else-if="!loading" class="flex items-center justify-center h-full text-s1-muted text-sm">No data</div>
          <LoadingSkeleton v-else :rows="3" />
        </div>
      </div>

      <div class="card p-5">
        <h3 class="text-sm font-semibold text-s1-text mb-4">Alerts by Product</h3>
        <div class="h-48">
          <Bar v-if="!loading && incidents.length" :data="alertsByProductChartData" :options="barChartOptions" />
          <div v-else-if="!loading" class="flex items-center justify-center h-full text-s1-muted text-sm">No data</div>
          <LoadingSkeleton v-else :rows="3" />
        </div>
      </div>
    </div>

    <!-- Recent Incidents table -->
    <div class="card">
      <div class="flex items-center justify-between px-5 py-4 border-b border-s1-border">
        <h3 class="text-sm font-semibold text-s1-text">Recent Incidents</h3>
        <RouterLink to="/sentinel/incidents" class="text-xs text-green-600 hover:underline">View all</RouterLink>
      </div>
      <LoadingSkeleton v-if="loading" :rows="5" />
      <div v-else class="divide-y divide-s1-border">
        <RouterLink
          v-for="inc in incidents.slice(0, 10)" :key="inc.name"
          :to="`/sentinel/incidents/${inc.name}`"
          class="block px-5 py-3 hover:bg-s1-hover transition-colors cursor-pointer"
        >
          <div class="flex items-center justify-between">
            <div class="text-sm text-s1-text truncate max-w-[50%]">{{ inc.properties.title }}</div>
            <div class="flex items-center gap-2">
              <span
                class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                :class="severityBadgeClass(inc.properties.severity)"
              >
                {{ inc.properties.severity }}
              </span>
              <span class="text-xs text-s1-muted bg-s1-hover px-2 py-0.5 rounded">
                {{ inc.properties.status }}
              </span>
            </div>
          </div>
          <div class="text-xs text-s1-muted mt-0.5">
            {{ inc.properties.providerName }} |
            {{ inc.properties.additionalData?.alertsCount ?? 0 }} alerts |
            {{ relativeTime(inc.properties.createdTimeUtc) }}
          </div>
        </RouterLink>
      </div>
      <div v-if="!loading && !incidents.length" class="py-8 text-center text-s1-muted text-sm">
        No recent incidents
      </div>
    </div>
  </div>
</template>
