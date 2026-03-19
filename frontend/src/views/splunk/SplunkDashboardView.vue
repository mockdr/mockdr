<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { Search, ShieldAlert, Database, RefreshCw, Zap } from 'lucide-vue-next'
import { Doughnut, Bar } from 'vue-chartjs'
import {
  Chart as ChartJS, ArcElement, Tooltip, Legend,
  BarElement, CategoryScale, LinearScale,
} from 'chart.js'
import { splunkNotableApi, splunkIndexApi } from '../../api/splunk'
import type { SplunkNotable, SplunkIndex, SplunkEntry } from '../../types/splunk'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

ChartJS.register(ArcElement, Tooltip, Legend, BarElement, CategoryScale, LinearScale)

const loading = ref(true)
const error = ref('')

const notables = ref<SplunkNotable[]>([])
const indexes = ref<SplunkEntry<SplunkIndex>[]>([])
const totalEvents = ref(0)
const openNotables = ref(0)

let timer: ReturnType<typeof setInterval>

const summaryCards = computed(() => [
  { label: 'Total Events', value: totalEvents.value, icon: Database, color: 'text-green-400', bg: 'bg-green-500/10' },
  { label: 'Notable Events (Open)', value: openNotables.value, icon: ShieldAlert, color: 'text-red-400', bg: 'bg-red-500/10' },
  { label: 'Indexes', value: indexes.value.length, icon: Search, color: 'text-blue-400', bg: 'bg-blue-500/10' },
  { label: 'HEC Status', value: 'Active', icon: Zap, color: 'text-yellow-400', bg: 'bg-yellow-500/10' },
])

const eventsByIndexChartData = computed(() => {
  const edrIndexes = indexes.value.filter(e =>
    ['sentinelone', 'crowdstrike', 'msdefender', 'elastic_security', 'cortex_xdr'].includes(e.name),
  )
  return {
    labels: edrIndexes.map(e => e.name),
    datasets: [{
      data: edrIndexes.map(e => parseInt(e.content.totalEventCount ?? '0', 10)),
      backgroundColor: ['#7C3AED', '#EF4444', '#3B82F6', '#F59E0B', '#F97316'],
      borderWidth: 0,
    }],
  }
})

const notableSeverityChartData = computed(() => {
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 }
  for (const n of notables.value) {
    const sev = (n.severity ?? 'medium').toLowerCase()
    counts[sev] = (counts[sev] ?? 0) + 1
  }
  const labels = Object.keys(counts).filter(k => counts[k] > 0)
  return {
    labels,
    datasets: [{
      data: labels.map(k => counts[k]),
      backgroundColor: ['#EF4444', '#F97316', '#EAB308', '#3B82F6', '#6B7280'],
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
    case 'critical': return 'bg-red-500/15 text-red-400'
    case 'high': return 'bg-orange-500/15 text-orange-400'
    case 'medium': return 'bg-yellow-500/15 text-yellow-400'
    case 'low': return 'bg-blue-500/15 text-blue-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function statusLabel(status: string): string {
  const labels: Record<string, string> = {
    '1': 'New', '2': 'In Progress', '3': 'Pending', '4': 'Resolved', '5': 'Closed',
  }
  return labels[status] ?? status
}

function formatTime(ts: string): string {
  if (!ts) return ''
  const d = new Date(parseFloat(ts) * 1000)
  return d.toLocaleString()
}

async function fetchAll(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const [notableRes, indexRes] = await Promise.all([
      splunkNotableApi.list(),
      splunkIndexApi.list(),
    ])
    notables.value = notableRes
    openNotables.value = notableRes.filter(n => n.status === '1' || n.status === '2').length

    indexes.value = indexRes.entry ?? []
    totalEvents.value = indexes.value.reduce(
      (sum, e) => sum + parseInt(e.content.totalEventCount ?? '0', 10), 0,
    )
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
          <span class="text-green-500 font-bold">SPL</span> Splunk SIEM Dashboard
        </h1>
        <p class="text-s1-muted text-sm">Splunk Enterprise Security overview — all EDR vendors</p>
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
        class="card p-5 border-l-2 border-l-green-500/50"
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
        <h3 class="text-sm font-semibold text-s1-text mb-4">Events by Index</h3>
        <div class="h-48">
          <Doughnut v-if="!loading && indexes.length" :data="eventsByIndexChartData" :options="chartOptions" />
          <div v-else-if="!loading" class="flex items-center justify-center h-full text-s1-muted text-sm">No data</div>
          <LoadingSkeleton v-else :rows="3" />
        </div>
      </div>

      <div class="card p-5">
        <h3 class="text-sm font-semibold text-s1-text mb-4">Notables by Severity</h3>
        <div class="h-48">
          <Bar v-if="!loading && notables.length" :data="notableSeverityChartData" :options="barChartOptions" />
          <div v-else-if="!loading" class="flex items-center justify-center h-full text-s1-muted text-sm">No data</div>
          <LoadingSkeleton v-else :rows="3" />
        </div>
      </div>
    </div>

    <!-- Recent Notables table -->
    <div class="card">
      <div class="flex items-center justify-between px-5 py-4 border-b border-s1-border">
        <h3 class="text-sm font-semibold text-s1-text">Recent Notable Events</h3>
        <RouterLink to="/splunk/notables" class="text-xs text-green-400 hover:underline">View all</RouterLink>
      </div>
      <LoadingSkeleton v-if="loading" :rows="5" />
      <div v-else class="divide-y divide-s1-border">
        <RouterLink
          v-for="n in notables.slice(0, 10)" :key="n.event_id"
          :to="`/splunk/notables/${n.event_id}`"
          class="block px-5 py-3 hover:bg-s1-hover transition-colors cursor-pointer"
        >
          <div class="flex items-center justify-between">
            <div class="text-sm text-s1-text truncate max-w-[50%]">{{ n.rule_name }}</div>
            <div class="flex items-center gap-2">
              <span
                class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                :class="severityBadgeClass(n.severity)"
              >
                {{ n.severity }}
              </span>
              <span class="text-xs text-s1-muted bg-s1-hover px-2 py-0.5 rounded">
                {{ statusLabel(n.status) }}
              </span>
            </div>
          </div>
          <div class="text-xs text-s1-muted mt-0.5">{{ n.dest }} | {{ n.owner }} | {{ formatTime(n.time) }}</div>
        </RouterLink>
      </div>
      <div v-if="!loading && !notables.length" class="py-8 text-center text-s1-muted text-sm">
        No notable events
      </div>
    </div>
  </div>
</template>
