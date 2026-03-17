<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ensureMdeAuth, mdeAlertsApi } from '../../api/defender'
import type { MdeAlert } from '../../types/defender'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const alerts = ref<MdeAlert[]>([])
const skip = ref(0)
const top = 25

// Filters
const filterSeverity = ref('')
const filterStatus = ref('')

function severityBadgeClass(severity: string): string {
  switch (severity) {
    case 'High': return 'bg-red-500/15 text-red-400'
    case 'Medium': return 'bg-orange-500/15 text-orange-400'
    case 'Low': return 'bg-yellow-500/15 text-yellow-400'
    case 'Informational': return 'bg-gray-500/15 text-gray-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function statusBadgeClass(status: string): string {
  switch (status) {
    case 'New': return 'bg-blue-500/15 text-blue-400'
    case 'InProgress': return 'bg-yellow-500/15 text-yellow-400'
    case 'Resolved': return 'bg-green-500/15 text-green-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function fetchAlerts(direction: 'next' | 'prev' | 'reset' = 'reset'): Promise<void> {
  loading.value = true
  try {
    await ensureMdeAuth()

    if (direction === 'next') {
      skip.value += top
    } else if (direction === 'prev') {
      skip.value = Math.max(0, skip.value - top)
    } else {
      skip.value = 0
    }

    const params: Record<string, unknown> = {
      $top: top,
      $skip: skip.value,
    }

    const filters: string[] = []
    if (filterSeverity.value) filters.push(`severity eq '${filterSeverity.value}'`)
    if (filterStatus.value) filters.push(`status eq '${filterStatus.value}'`)
    if (filters.length) params['$filter'] = filters.join(' and ')

    const res = await mdeAlertsApi.list(params)
    alerts.value = res.value ?? []
  } finally {
    loading.value = false
  }
}

const hasPrev = computed(() => skip.value > 0)
const hasNext = computed(() => alerts.value.length === top)

watch([filterSeverity, filterStatus], () => fetchAlerts())

onMounted(() => fetchAlerts())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="text-green-500 font-bold">MDE</span> Alerts
        </h1>
        <p class="text-s1-muted text-sm">Defender for Endpoint alerts</p>
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
        <option value="High">High</option>
        <option value="Medium">Medium</option>
        <option value="Low">Low</option>
        <option value="Informational">Informational</option>
      </select>
      <select v-model="filterStatus" class="select">
        <option value="">All Statuses</option>
        <option value="New">New</option>
        <option value="InProgress">In Progress</option>
        <option value="Resolved">Resolved</option>
      </select>
    </div>

    <!-- Table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Title</th>
            <th class="table-header text-left">Severity</th>
            <th class="table-header text-left">Status</th>
            <th class="table-header text-left">Category</th>
            <th class="table-header text-left">Machine</th>
            <th class="table-header text-left">Created</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !alerts.length" :rows="8" />
          <template v-else>
            <tr v-for="alert in alerts" :key="alert.alertId" class="table-row">
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm truncate max-w-[200px]">{{ alert.title }}</div>
                <div class="text-xs text-s1-muted">{{ alert.detectionSource }}</div>
              </td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="severityBadgeClass(alert.severity)">
                  {{ alert.severity }}
                </span>
              </td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="statusBadgeClass(alert.status)">
                  {{ alert.status }}
                </span>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ alert.category }}</td>
              <td class="table-cell">
                <span class="font-mono text-xs text-s1-muted">{{ alert.computerDnsName ?? alert.machineId }}</span>
              </td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(alert.creationTime) }}</td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !alerts.length"
        icon="--"
        title="No alerts found"
        description="No alerts match your current filters."
      />

      <!-- Pagination -->
      <div v-if="alerts.length > 0" class="p-4 flex items-center justify-between border-t border-s1-border">
        <button @click="fetchAlerts('prev')" class="btn-ghost text-sm" :disabled="!hasPrev || loading">
          Previous
        </button>
        <span class="text-xs text-s1-muted">
          Showing {{ skip + 1 }}–{{ skip + alerts.length }}
        </span>
        <button @click="fetchAlerts('next')" class="btn-ghost text-sm" :disabled="!hasNext || loading">
          Next
        </button>
      </div>
    </div>
  </div>
</template>
