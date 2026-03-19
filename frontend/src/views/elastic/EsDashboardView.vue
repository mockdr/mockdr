<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { Monitor, ShieldAlert, FileCheck, Briefcase, RefreshCw } from 'lucide-vue-next'
import { Doughnut } from 'vue-chartjs'
import {
  Chart as ChartJS, ArcElement, Tooltip, Legend,
} from 'chart.js'
import { esEndpointsApi, esRulesApi, esAlertsApi, esCasesApi } from '../../api/elastic'
import type { EsEndpoint, EsRule, EsAlert } from '../../types/elastic'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

ChartJS.register(ArcElement, Tooltip, Legend)

const loading = ref(true)
const error = ref('')

const endpointCount = ref(0)
const ruleCount = ref(0)
const alertCount = ref(0)
const caseCount = ref(0)

const endpoints = ref<EsEndpoint[]>([])
const rules = ref<EsRule[]>([])
const alerts = ref<EsAlert[]>([])

let timer: ReturnType<typeof setInterval>

const summaryCards = computed(() => [
  { label: 'Endpoints', value: endpointCount.value, icon: Monitor, color: 'text-purple-400', bg: 'bg-purple-500/10' },
  { label: 'Detection Rules', value: ruleCount.value, icon: FileCheck, color: 'text-teal-400', bg: 'bg-teal-500/10' },
  { label: 'Alerts', value: alertCount.value, icon: ShieldAlert, color: 'text-orange-400', bg: 'bg-orange-500/10' },
  { label: 'Cases', value: caseCount.value, icon: Briefcase, color: 'text-blue-400', bg: 'bg-blue-500/10' },
])

const statusChartData = computed(() => {
  const counts: Record<string, number> = {}
  for (const ep of endpoints.value) {
    const key = ep.agent_status ?? 'Unknown'
    counts[key] = (counts[key] ?? 0) + 1
  }
  return {
    labels: Object.keys(counts),
    datasets: [{
      data: Object.values(counts),
      backgroundColor: ['#A855F7', '#14B8A6', '#F97316', '#6B7280'],
      borderWidth: 0,
    }],
  }
})

const ruleSeverityChartData = computed(() => {
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const r of rules.value) {
    const sev = r.severity ?? 'low'
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

const alertStatusChartData = computed(() => {
  const counts: Record<string, number> = {}
  for (const a of alerts.value) {
    const key = a.status ?? 'open'
    counts[key] = (counts[key] ?? 0) + 1
  }
  return {
    labels: Object.keys(counts),
    datasets: [{
      data: Object.values(counts),
      backgroundColor: ['#3B82F6', '#EAB308', '#22C55E', '#6B7280'],
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
    const [epRes, rulesRes, alertsRes, casesRes] = await Promise.all([
      esEndpointsApi.list({ per_page: 50 }),
      esRulesApi.find({ per_page: 50 }),
      esAlertsApi.search({ query: { match_all: {} }, size: 50 }),
      esCasesApi.find({ per_page: 1 }),
    ])

    endpoints.value = epRes.data ?? []
    endpointCount.value = epRes.total ?? endpoints.value.length

    rules.value = rulesRes.data ?? []
    ruleCount.value = rulesRes.total ?? rules.value.length

    const hits = alertsRes.hits?.hits ?? []
    alerts.value = hits.map(h => ({ ...h._source, id: h._id }))
    alertCount.value = alertsRes.hits?.total?.value ?? alerts.value.length

    caseCount.value = casesRes.total ?? 0
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
          <span class="text-purple-500 font-bold">ES</span> Elastic Security Dashboard
        </h1>
        <p class="text-s1-muted text-sm">Elastic Security overview</p>
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
        class="card p-5 border-l-2 border-l-purple-500/50"
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
        <h3 class="text-sm font-semibold text-s1-text mb-4">Endpoint Status</h3>
        <div class="h-40">
          <Doughnut v-if="!loading && endpoints.length" :data="statusChartData" :options="chartOptions" />
          <div v-else-if="!loading" class="flex items-center justify-center h-full text-s1-muted text-sm">No data</div>
          <LoadingSkeleton v-else :rows="3" />
        </div>
      </div>

      <div class="card p-5">
        <h3 class="text-sm font-semibold text-s1-text mb-4">Rule Severity</h3>
        <div class="h-40">
          <Doughnut v-if="!loading && rules.length" :data="ruleSeverityChartData" :options="chartOptions" />
          <div v-else-if="!loading" class="flex items-center justify-center h-full text-s1-muted text-sm">No data</div>
          <LoadingSkeleton v-else :rows="3" />
        </div>
      </div>

      <div class="card p-5">
        <h3 class="text-sm font-semibold text-s1-text mb-4">Alert Status</h3>
        <div class="h-40">
          <Doughnut v-if="!loading && alerts.length" :data="alertStatusChartData" :options="chartOptions" />
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
          <RouterLink to="/elastic/alerts" class="text-xs text-purple-400 hover:underline">View all</RouterLink>
        </div>
        <LoadingSkeleton v-if="loading" :rows="5" />
        <div v-else class="divide-y divide-s1-border">
          <div
            v-for="alert in alerts.slice(0, 5)" :key="alert.id"
            class="px-5 py-3 hover:bg-s1-hover transition-colors cursor-pointer"
          >
            <div class="flex items-center justify-between">
              <div class="text-sm text-s1-text truncate max-w-[70%]">{{ alert.rule_name }}</div>
              <span
                class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                :class="{
                  'bg-red-500/15 text-red-400': alert.severity === 'critical',
                  'bg-orange-500/15 text-orange-400': alert.severity === 'high',
                  'bg-yellow-500/15 text-yellow-400': alert.severity === 'medium',
                  'bg-blue-500/15 text-blue-400': alert.severity === 'low',
                }"
              >
                {{ alert.severity }}
              </span>
            </div>
            <div class="text-xs text-s1-muted mt-0.5">{{ alert.host_name }} | {{ alert.status }}</div>
          </div>
        </div>
        <div v-if="!loading && !alerts.length" class="py-8 text-center text-s1-muted text-sm">
          No recent alerts
        </div>
      </div>

      <!-- Detection Rules -->
      <div class="card">
        <div class="flex items-center justify-between px-5 py-4 border-b border-s1-border">
          <h3 class="text-sm font-semibold text-s1-text">Detection Rules</h3>
          <RouterLink to="/elastic/rules" class="text-xs text-purple-400 hover:underline">View all</RouterLink>
        </div>
        <LoadingSkeleton v-if="loading" :rows="5" />
        <div v-else class="divide-y divide-s1-border">
          <div
            v-for="rule in rules.slice(0, 5)" :key="rule.id"
            class="px-5 py-3 hover:bg-s1-hover transition-colors cursor-pointer"
          >
            <div class="flex items-center justify-between">
              <div class="text-sm text-s1-text truncate max-w-[70%]">{{ rule.name }}</div>
              <span
                class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                :class="rule.enabled ? 'bg-green-500/15 text-green-400' : 'bg-gray-500/15 text-gray-400'"
              >
                {{ rule.enabled ? 'Enabled' : 'Disabled' }}
              </span>
            </div>
            <div class="text-xs text-s1-muted mt-0.5">{{ rule.severity }} | Risk: {{ rule.risk_score }}</div>
          </div>
        </div>
        <div v-if="!loading && !rules.length" class="py-8 text-center text-s1-muted text-sm">
          No detection rules
        </div>
      </div>
    </div>
  </div>
</template>
