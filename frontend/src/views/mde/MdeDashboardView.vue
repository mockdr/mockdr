<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { Monitor, ShieldAlert, Target, RefreshCw } from 'lucide-vue-next'
import { Doughnut } from 'vue-chartjs'
import {
  Chart as ChartJS, ArcElement, Tooltip, Legend,
} from 'chart.js'
import { ensureMdeAuth, mdeMachinesApi, mdeAlertsApi, mdeIndicatorsApi } from '../../api/defender'
import type { MdeMachine, MdeAlert } from '../../types/defender'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

ChartJS.register(ArcElement, Tooltip, Legend)

const loading = ref(true)
const error = ref('')

const machineCount = ref(0)
const alertCount = ref(0)
const indicatorCount = ref(0)

const machines = ref<MdeMachine[]>([])
const alerts = ref<MdeAlert[]>([])

let timer: ReturnType<typeof setInterval>

const summaryCards = computed(() => [
  { label: 'Total Machines', value: machineCount.value, icon: Monitor, color: 'text-green-400', bg: 'bg-green-500/10' },
  { label: 'Alerts', value: alertCount.value, icon: ShieldAlert, color: 'text-emerald-400', bg: 'bg-emerald-500/10' },
  { label: 'Indicators', value: indicatorCount.value, icon: Target, color: 'text-teal-400', bg: 'bg-teal-500/10' },
])

const platformChartData = computed(() => {
  const counts: Record<string, number> = {}
  for (const m of machines.value) {
    const key = m.osPlatform ?? 'Unknown'
    counts[key] = (counts[key] ?? 0) + 1
  }
  return {
    labels: Object.keys(counts),
    datasets: [{
      data: Object.values(counts),
      backgroundColor: ['#22C55E', '#10B981', '#14B8A6', '#06B6D4', '#6B7280'],
      borderWidth: 0,
    }],
  }
})

const severityChartData = computed(() => {
  const counts: Record<string, number> = { High: 0, Medium: 0, Low: 0, Informational: 0 }
  for (const a of alerts.value) {
    const sev = a.severity ?? 'Unknown'
    counts[sev] = (counts[sev] ?? 0) + 1
  }
  return {
    labels: Object.keys(counts).filter(k => counts[k] > 0),
    datasets: [{
      data: Object.keys(counts).filter(k => counts[k] > 0).map(k => counts[k]),
      backgroundColor: ['#EF4444', '#F97316', '#EAB308', '#6B7280'],
      borderWidth: 0,
    }],
  }
})

const riskChartData = computed(() => {
  const counts: Record<string, number> = {}
  for (const m of machines.value) {
    const key = m.riskScore ?? 'None'
    counts[key] = (counts[key] ?? 0) + 1
  }
  return {
    labels: Object.keys(counts),
    datasets: [{
      data: Object.values(counts),
      backgroundColor: ['#EF4444', '#F97316', '#EAB308', '#22C55E', '#6B7280'],
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
    await ensureMdeAuth()

    const [machinesRes, alertsRes, indicatorsRes] = await Promise.all([
      mdeMachinesApi.list({ $top: 50 }),
      mdeAlertsApi.list({ $top: 50 }),
      mdeIndicatorsApi.list({ $top: 0 }),
    ])

    machines.value = machinesRes.value ?? []
    alerts.value = alertsRes.value ?? []
    machineCount.value = machines.value.length
    alertCount.value = alerts.value.length
    indicatorCount.value = indicatorsRes.value?.length ?? 0
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
          <span class="text-green-500 font-bold">MDE</span> Defender Dashboard
        </h1>
        <p class="text-s1-muted text-sm">Microsoft Defender for Endpoint overview</p>
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
    <div class="grid grid-cols-3 gap-4">
      <div class="card p-5">
        <h3 class="text-sm font-semibold text-s1-text mb-4">OS Platform Distribution</h3>
        <div class="h-40">
          <Doughnut v-if="!loading && machines.length" :data="platformChartData" :options="chartOptions" />
          <div v-else-if="!loading" class="flex items-center justify-center h-full text-s1-muted text-sm">No data</div>
          <LoadingSkeleton v-else :rows="3" />
        </div>
      </div>

      <div class="card p-5">
        <h3 class="text-sm font-semibold text-s1-text mb-4">Alert Severity</h3>
        <div class="h-40">
          <Doughnut v-if="!loading && alerts.length" :data="severityChartData" :options="chartOptions" />
          <div v-else-if="!loading" class="flex items-center justify-center h-full text-s1-muted text-sm">No data</div>
          <LoadingSkeleton v-else :rows="3" />
        </div>
      </div>

      <div class="card p-5">
        <h3 class="text-sm font-semibold text-s1-text mb-4">Machine Risk Score</h3>
        <div class="h-40">
          <Doughnut v-if="!loading && machines.length" :data="riskChartData" :options="chartOptions" />
          <div v-else-if="!loading" class="flex items-center justify-center h-full text-s1-muted text-sm">No data</div>
          <LoadingSkeleton v-else :rows="3" />
        </div>
      </div>
    </div>

    <!-- Tables row -->
    <div class="grid grid-cols-2 gap-4">
      <!-- Recent Alerts -->
      <div class="card">
        <div class="flex items-center justify-between px-5 py-4 border-b border-s1-border">
          <h3 class="text-sm font-semibold text-s1-text">Recent Alerts</h3>
          <RouterLink to="/defender/alerts" class="text-xs text-green-400 hover:underline">View all</RouterLink>
        </div>
        <LoadingSkeleton v-if="loading" :rows="5" />
        <div v-else class="divide-y divide-s1-border">
          <div
            v-for="alert in alerts.slice(0, 5)" :key="alert.alertId"
            class="px-5 py-3 hover:bg-s1-hover transition-colors cursor-pointer"
          >
            <div class="flex items-center justify-between">
              <div class="text-sm text-s1-text truncate max-w-[70%]">{{ alert.title }}</div>
              <span
                class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                :class="{
                  'bg-red-500/15 text-red-400': alert.severity === 'High',
                  'bg-orange-500/15 text-orange-400': alert.severity === 'Medium',
                  'bg-yellow-500/15 text-yellow-400': alert.severity === 'Low',
                  'bg-gray-500/15 text-gray-400': alert.severity === 'Informational',
                }"
              >
                {{ alert.severity }}
              </span>
            </div>
            <div class="text-xs text-s1-muted mt-0.5">{{ alert.category }} | {{ alert.status }}</div>
          </div>
        </div>
        <div v-if="!loading && !alerts.length" class="py-8 text-center text-s1-muted text-sm">
          No recent alerts
        </div>
      </div>

      <!-- Recent Machines -->
      <div class="card">
        <div class="flex items-center justify-between px-5 py-4 border-b border-s1-border">
          <h3 class="text-sm font-semibold text-s1-text">Machines</h3>
          <RouterLink to="/defender/machines" class="text-xs text-green-400 hover:underline">View all</RouterLink>
        </div>
        <LoadingSkeleton v-if="loading" :rows="5" />
        <div v-else class="divide-y divide-s1-border">
          <div
            v-for="machine in machines.slice(0, 5)" :key="machine.machineId"
            class="px-5 py-3 hover:bg-s1-hover transition-colors cursor-pointer"
          >
            <div class="flex items-center justify-between">
              <div class="text-sm text-s1-text truncate max-w-[70%]">{{ machine.computerDnsName }}</div>
              <span
                class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                :class="{
                  'bg-green-500/15 text-green-400': machine.healthStatus === 'Active',
                  'bg-yellow-500/15 text-yellow-400': machine.healthStatus === 'Inactive',
                  'bg-red-500/15 text-red-400': machine.healthStatus === 'ImpairedCommunication',
                  'bg-gray-500/15 text-gray-400': !['Active', 'Inactive', 'ImpairedCommunication'].includes(machine.healthStatus),
                }"
              >
                {{ machine.healthStatus }}
              </span>
            </div>
            <div class="text-xs text-s1-muted mt-0.5">{{ machine.osPlatform }} | Risk: {{ machine.riskScore }}</div>
          </div>
        </div>
        <div v-if="!loading && !machines.length" class="py-8 text-center text-s1-muted text-sm">
          No machines
        </div>
      </div>
    </div>
  </div>
</template>
