<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { xdrAlertsApi } from '../../api/cortex'
import type { XdrAlert } from '../../types/cortex'
import { formatEpoch } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const alerts = ref<XdrAlert[]>([])
const totalCount = ref(0)

const filterSeverity = ref('')
const filterSource = ref('')

function severityBadgeClass(severity: string): string {
  switch ((severity ?? '').toLowerCase()) {
    case 'critical': return 'bg-red-500/15 text-red-400'
    case 'high': return 'bg-orange-500/15 text-orange-400'
    case 'medium': return 'bg-yellow-500/15 text-yellow-400'
    case 'low': return 'bg-blue-500/15 text-blue-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

const filteredAlerts = computed(() => {
  let result = alerts.value
  if (filterSeverity.value) {
    result = result.filter(a => (a.severity ?? '').toLowerCase() === filterSeverity.value)
  }
  if (filterSource.value) {
    result = result.filter(a => a.source === filterSource.value)
  }
  return result
})

const uniqueSources = computed(() => {
  const sources = new Set<string>()
  for (const a of alerts.value) {
    if (a.source) sources.add(a.source)
  }
  return [...sources].sort()
})

async function fetchAlerts(): Promise<void> {
  loading.value = true
  try {
    const res = await xdrAlertsApi.list()
    alerts.value = res.reply?.alerts ?? []
    totalCount.value = res.reply?.total_count ?? alerts.value.length
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchAlerts())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="text-orange-500 font-bold">XDR</span> Alerts
        </h1>
        <p class="text-s1-muted text-sm">Cortex XDR alert monitoring</p>
      </div>
      <button @click="fetchAlerts()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Filter bar -->
    <div class="card p-4 flex flex-wrap gap-3">
      <select v-model="filterSeverity" class="select">
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <select v-model="filterSource" class="select">
        <option value="">All Sources</option>
        <option v-for="src in uniqueSources" :key="src" :value="src">{{ src }}</option>
      </select>
      <div class="ml-auto text-xs text-s1-muted self-center">
        {{ filteredAlerts.length }} of {{ totalCount }} alerts
      </div>
    </div>

    <!-- Table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Alert ID</th>
            <th class="table-header text-left">Name</th>
            <th class="table-header text-left">Severity</th>
            <th class="table-header text-left">Category</th>
            <th class="table-header text-left">Source</th>
            <th class="table-header text-left">Action</th>
            <th class="table-header text-left">Host</th>
            <th class="table-header text-left">Detected</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !alerts.length" :rows="8" />
          <template v-else>
            <tr
              v-for="alert in filteredAlerts" :key="alert.alert_id"
              class="table-row"
            >
              <td class="table-cell">
                <span class="text-sm font-mono text-s1-text">{{ alert.alert_id }}</span>
              </td>
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm truncate max-w-[200px]">{{ alert.name }}</div>
                <div v-if="alert.mitre_technique_id_and_name" class="text-xs text-s1-muted truncate max-w-[200px]">
                  {{ alert.mitre_technique_id_and_name }}
                </div>
              </td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="severityBadgeClass(alert.severity)">
                  {{ alert.severity }}
                </span>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ alert.category || '--' }}</td>
              <td class="table-cell text-sm text-s1-subtle">{{ alert.source || '--' }}</td>
              <td class="table-cell text-sm text-s1-subtle">{{ alert.action || '--' }}</td>
              <td class="table-cell">
                <div class="text-sm text-s1-text">{{ alert.host_name || '--' }}</div>
                <div class="text-xs text-s1-muted">{{ alert.host_ip || '' }}</div>
              </td>
              <td class="table-cell text-xs text-s1-muted">{{ formatEpoch(alert.detection_timestamp) }}</td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !filteredAlerts.length"
        icon="--"
        title="No alerts found"
        description="No alerts match your current filters."
      />
    </div>
  </div>
</template>
