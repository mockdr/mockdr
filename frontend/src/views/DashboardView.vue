<script setup lang="ts">
import { onMounted, onUnmounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import { Monitor, ShieldAlert, Bell, WifiOff, RefreshCw } from 'lucide-vue-next'
import { Doughnut } from 'vue-chartjs'
import {
  Chart as ChartJS, ArcElement, Tooltip, Legend,
  CategoryScale, LinearScale, PointElement, LineElement, Filler,
} from 'chart.js'
import { useDashboardStore } from '../stores/dashboard'
import StatusBadge from '../components/shared/StatusBadge.vue'
import LoadingSkeleton from '../components/shared/LoadingSkeleton.vue'

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, Filler)

const router = useRouter()
const dash = useDashboardStore()
let timer: ReturnType<typeof setInterval>

const summaryCards = computed(() => [
  { label: 'Total Endpoints', value: dash.summary.totalAgents, icon: Monitor, color: 'text-s1-cyan', bg: 'bg-s1-cyan/10' },
  { label: 'Active Threats', value: dash.summary.activeThreats, icon: ShieldAlert, color: 'text-s1-danger', bg: 'bg-s1-danger/10' },
  { label: 'Unresolved Alerts', value: dash.summary.unresolvedAlerts, icon: Bell, color: 'text-s1-warning', bg: 'bg-s1-warning/10' },
  { label: 'Endpoints Offline', value: dash.summary.offlineAgents, icon: WifiOff, color: 'text-s1-muted', bg: 'bg-s1-muted/10' },
])

const osChartData = computed(() => ({
  labels: ['Windows', 'macOS', 'Linux'],
  datasets: [{
    data: [dash.agentsByOs.windows, dash.agentsByOs.macos, dash.agentsByOs.linux],
    backgroundColor: ['#6E45E2', '#00C2FF', '#00D8A0'],
    borderWidth: 0,
  }],
}))

const healthChartData = computed(() => ({
  labels: ['Connected', 'Disconnected', 'Inactive'],
  datasets: [{
    data: [dash.agentsByStatus.connected, dash.agentsByStatus.disconnected, dash.agentsByStatus.inactive],
    backgroundColor: ['#00D8A0', '#FF4B4B', '#64748B'],
    borderWidth: 0,
  }],
}))

const chartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: { legend: { position: 'bottom' as const, labels: { color: '#94A3B8', font: { size: 11 }, padding: 12 } } },
}

onMounted(() => {
  dash.fetchAll()
  timer = setInterval(() => dash.fetchAll(), 60000)
})

onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text">Dashboard</h1>
        <p class="text-s1-muted text-sm">Threat and endpoint overview · auto-refreshes every 60s</p>
      </div>
      <button @click="dash.fetchAll()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="dash.loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <div v-if="dash.error" class="error-banner">{{ dash.error }}</div>

    <!-- Summary cards -->
    <div class="grid grid-cols-4 gap-4">
      <div v-for="card in summaryCards" :key="card.label" class="card p-5">
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
      <!-- OS Distribution -->
      <div class="card p-5">
        <h3 class="text-sm font-semibold text-s1-text mb-4">OS Distribution</h3>
        <div class="h-40">
          <Doughnut v-if="!dash.loading" :data="osChartData" :options="chartOptions" />
        </div>
      </div>

      <!-- Agent Health -->
      <div class="card p-5">
        <h3 class="text-sm font-semibold text-s1-text mb-4">Agent Health</h3>
        <div class="h-40">
          <Doughnut v-if="!dash.loading" :data="healthChartData" :options="chartOptions" />
        </div>
      </div>

      <!-- Quick stats -->
      <div class="card p-5 flex flex-col justify-between">
        <h3 class="text-sm font-semibold text-s1-text mb-4">Protection Status</h3>
        <div class="space-y-3">
          <div class="flex items-center justify-between">
            <span class="text-sm text-s1-muted">Infected Endpoints</span>
            <span class="font-semibold text-s1-danger">{{ dash.summary.infectedAgents }}</span>
          </div>
          <div class="flex items-center justify-between">
            <span class="text-sm text-s1-muted">Protected Endpoints</span>
            <span class="font-semibold text-s1-success">{{ dash.summary.totalAgents - dash.summary.infectedAgents }}</span>
          </div>
          <div class="w-full bg-s1-border rounded-full h-1.5 mt-2">
            <div
              class="bg-s1-success h-1.5 rounded-full transition-all"
              :style="{ width: dash.summary.totalAgents ? `${((dash.summary.totalAgents - dash.summary.infectedAgents) / dash.summary.totalAgents * 100).toFixed(0)}%` : '0%' }"
            ></div>
          </div>
          <div class="text-xs text-s1-muted text-right">
            {{ dash.summary.totalAgents ? ((dash.summary.totalAgents - dash.summary.infectedAgents) / dash.summary.totalAgents * 100).toFixed(1) : 0 }}% protected
          </div>
        </div>
      </div>
    </div>

    <!-- Tables row -->
    <div class="grid grid-cols-2 gap-4">
      <!-- Recent Threats -->
      <div class="card">
        <div class="flex items-center justify-between px-5 py-4 border-b border-s1-border">
          <h3 class="text-sm font-semibold text-s1-text">Recent Threats</h3>
          <RouterLink to="/threats" class="text-xs text-s1-primary hover:underline">View all</RouterLink>
        </div>
        <LoadingSkeleton v-if="dash.loading" :rows="5" />
        <table v-else class="w-full">
          <tbody>
            <tr
              v-for="threat in dash.recentThreats" :key="threat.id"
              class="table-row"
              @click="router.push(`/threats/${threat.id}`)"
            >
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm truncate max-w-[140px]">{{ threat.threatInfo.threatName }}</div>
                <div class="text-xs text-s1-muted">{{ threat.agentDetectionInfo.agentComputerName }}</div>
              </td>
              <td class="table-cell">
                <StatusBadge :status="threat.threatInfo.mitigationStatus" type="threat" />
              </td>
              <td class="table-cell text-xs text-s1-muted">
                {{ threat.threatInfo.classification }}
              </td>
            </tr>
          </tbody>
        </table>
        <div v-if="!dash.loading && !dash.recentThreats.length" class="py-8 text-center text-s1-muted text-sm">
          🎉 No recent threats
        </div>
      </div>

      <!-- Recent Activities -->
      <div class="card">
        <div class="flex items-center justify-between px-5 py-4 border-b border-s1-border">
          <h3 class="text-sm font-semibold text-s1-text">Recent Activity</h3>
          <RouterLink to="/activities" class="text-xs text-s1-primary hover:underline">View all</RouterLink>
        </div>
        <LoadingSkeleton v-if="dash.loading" :rows="5" />
        <div v-else class="divide-y divide-s1-border">
          <div
            v-for="act in dash.recentActivities" :key="act.id"
            class="px-5 py-3 hover:bg-s1-hover transition-colors"
          >
            <div class="text-sm text-s1-text">{{ act.description }}</div>
            <div class="text-xs text-s1-muted mt-0.5">{{ act.createdAt?.slice(0, 10) }}</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
