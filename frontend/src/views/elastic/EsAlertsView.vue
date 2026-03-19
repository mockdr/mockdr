<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { esAlertsApi } from '../../api/elastic'
import type { EsAlert } from '../../types/elastic'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const alerts = ref<EsAlert[]>([])
const total = ref(0)
const from = ref(0)
const size = 25

// Filters
const filterSeverity = ref('')
const filterStatus = ref('')

// Selection for bulk status update
const selected = ref<Set<string>>(new Set())

function severityBadgeClass(severity: string): string {
  switch (severity) {
    case 'critical': return 'bg-red-500/15 text-red-400'
    case 'high': return 'bg-orange-500/15 text-orange-400'
    case 'medium': return 'bg-yellow-500/15 text-yellow-400'
    case 'low': return 'bg-blue-500/15 text-blue-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function statusBadgeClass(status: string): string {
  switch (status) {
    case 'open': return 'bg-blue-500/15 text-blue-400'
    case 'in-progress':
    case 'acknowledged': return 'bg-yellow-500/15 text-yellow-400'
    case 'closed': return 'bg-green-500/15 text-green-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function fetchAlerts(direction: 'next' | 'prev' | 'reset' = 'reset'): Promise<void> {
  loading.value = true
  try {
    if (direction === 'next') {
      from.value += size
    } else if (direction === 'prev') {
      from.value = Math.max(0, from.value - size)
    } else {
      from.value = 0
    }

    const musts: Record<string, unknown>[] = []
    if (filterSeverity.value) musts.push({ match: { severity: filterSeverity.value } })
    if (filterStatus.value) musts.push({ match: { status: filterStatus.value } })

    const body: Record<string, unknown> = {
      from: from.value,
      size,
      query: musts.length > 0 ? { bool: { must: musts } } : { match_all: {} },
      sort: [{ timestamp: { order: 'desc' } }],
    }

    const res = await esAlertsApi.search(body)
    const hits = res.hits?.hits ?? []
    alerts.value = hits.map(h => ({ ...h._source, id: h._id }))
    total.value = res.hits?.total?.value ?? alerts.value.length
  } finally {
    loading.value = false
  }
}

const hasPrev = computed(() => from.value > 0)
const hasNext = computed(() => from.value + size < total.value)

async function bulkUpdateStatus(newStatus: string): Promise<void> {
  if (selected.value.size === 0) return
  loading.value = true
  try {
    await esAlertsApi.updateStatus({
      signal_ids: [...selected.value],
      status: newStatus,
    })
    selected.value.clear()
    await fetchAlerts()
  } finally {
    loading.value = false
  }
}

watch([filterSeverity, filterStatus], () => fetchAlerts())

onMounted(() => fetchAlerts())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="text-purple-500 font-bold">ES</span> Alerts
        </h1>
        <p class="text-s1-muted text-sm">{{ total }} alerts total</p>
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
      <select v-model="filterStatus" class="select">
        <option value="">All Statuses</option>
        <option value="open">Open</option>
        <option value="acknowledged">Acknowledged</option>
        <option value="closed">Closed</option>
      </select>
    </div>

    <!-- Bulk action bar -->
    <Transition name="slide-down">
      <div v-if="selected.size > 0" class="card px-4 py-3 flex items-center gap-3 border-purple-500/40">
        <span class="text-sm text-s1-text font-medium">{{ selected.size }} selected</span>
        <div class="h-4 w-px bg-s1-border"></div>
        <button @click="bulkUpdateStatus('acknowledged')" class="btn-ghost text-xs text-yellow-400">Acknowledge</button>
        <button @click="bulkUpdateStatus('closed')" class="btn-ghost text-xs text-green-400">Close</button>
        <button @click="bulkUpdateStatus('open')" class="btn-ghost text-xs text-blue-400">Reopen</button>
      </div>
    </Transition>

    <!-- Table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header w-10">
              <input type="checkbox"
                :checked="alerts.length > 0 && alerts.every(a => selected.has(a.id))"
                @change="alerts.every(a => selected.has(a.id)) ? selected.clear() : alerts.forEach(a => selected.add(a.id))"
                class="rounded border-s1-border bg-s1-bg accent-purple-500" />
            </th>
            <th class="table-header text-left">Rule Name</th>
            <th class="table-header text-left">Severity</th>
            <th class="table-header text-left">Status</th>
            <th class="table-header text-left">Host</th>
            <th class="table-header text-left">Timestamp</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !alerts.length" :rows="8" />
          <template v-else>
            <tr v-for="alert in alerts" :key="alert.id" class="table-row"
              :class="selected.has(alert.id) ? 'bg-purple-500/5' : ''">
              <td class="table-cell" @click.stop>
                <input type="checkbox" :checked="selected.has(alert.id)"
                  @change="selected.has(alert.id) ? selected.delete(alert.id) : selected.add(alert.id)"
                  class="rounded border-s1-border bg-s1-bg accent-purple-500" />
              </td>
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm truncate max-w-[250px]">{{ alert.rule_name }}</div>
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
              <td class="table-cell text-sm text-s1-subtle">{{ alert.host_name }}</td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(alert.timestamp) }}</td>
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
          Showing {{ from + 1 }}–{{ from + alerts.length }} of {{ total }}
        </span>
        <button @click="fetchAlerts('next')" class="btn-ghost text-sm" :disabled="!hasNext || loading">
          Next
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.slide-down-enter-active, .slide-down-leave-active { transition: all 0.2s; }
.slide-down-enter-from, .slide-down-leave-to { opacity: 0; transform: translateY(-8px); }
</style>
