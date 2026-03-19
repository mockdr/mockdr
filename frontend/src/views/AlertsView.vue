<script setup lang="ts">
import { ref, watch, onMounted } from 'vue'
import { useDebounce } from '@vueuse/core'
import { alertsApi } from '../api/alerts'
import StatusBadge from '../components/shared/StatusBadge.vue'
import LoadingSkeleton from '../components/shared/LoadingSkeleton.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import type { Alert } from '../types'

const items = ref<Alert[]>([])
const total = ref(0)
const nextCursor = ref<string | null>(null)
const loading = ref(true)
const query = ref('')
const debouncedQuery = useDebounce(query, 300)
const severity = ref('')
const incidentStatus = ref('')

const SEVERITIES = ['', 'Critical', 'High', 'Medium', 'Low', 'Info']
const STATUSES = ['', 'Unresolved', 'In progress', 'Resolved']

async function fetchList(reset = true): Promise<void> {
  if (reset) { items.value = []; nextCursor.value = null }
  loading.value = true
  try {
    const params: Record<string, unknown> = { limit: 25 }
    if (nextCursor.value) params['cursor'] = nextCursor.value
    if (query.value) params['query'] = query.value
    if (severity.value) params['severities'] = severity.value
    if (incidentStatus.value) params['incidentStatuses'] = incidentStatus.value
    const res = await alertsApi.list(params)
    items.value = reset ? res.data : [...items.value, ...res.data]
    total.value = res.pagination.totalItems
    nextCursor.value = res.pagination.nextCursor
  } finally {
    loading.value = false
  }
}

watch(debouncedQuery, () => fetchList())

onMounted(() => fetchList())

const SEVERITY_COLOR: Record<string, string> = {
  Critical: 'text-s1-danger',
  High: 'text-s1-warning',
  Medium: 'text-yellow-400',
  Low: 'text-s1-cyan',
  Info: 'text-s1-muted',
}
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-s1-text">Alerts</h1>
        <p class="text-s1-muted text-sm">{{ total }} total alerts</p>
      </div>
    </div>

    <!-- Filters -->
    <div class="card p-3 flex flex-wrap gap-3">
      <input
        v-model="query"
        aria-label="Search alerts"
        class="input flex-1 min-w-40" placeholder="Search alerts..."
      />
      <select v-model="severity" @change="fetchList()" aria-label="Filter by severity" class="input w-40">
        <option value="">All Severities</option>
        <option v-for="s in SEVERITIES.slice(1)" :key="s" :value="s">{{ s }}</option>
      </select>
      <select v-model="incidentStatus" @change="fetchList()" aria-label="Filter by status" class="input w-40">
        <option value="">All Statuses</option>
        <option v-for="s in STATUSES.slice(1)" :key="s" :value="s">{{ s.replace(/_/g, ' ') }}</option>
      </select>
    </div>

    <!-- Table -->
    <div class="card overflow-hidden">
      <div v-if="loading && !items.length"><LoadingSkeleton :rows="8" /></div>
      <EmptyState v-else-if="!items.length" title="No alerts found" description="No alerts match your current filters" />
      <table v-else class="w-full text-sm">
        <thead class="border-b border-s1-border">
          <tr class="text-left text-xs text-s1-muted uppercase tracking-wide">
            <th class="px-4 py-3">Severity</th>
            <th class="px-4 py-3">Rule</th>
            <th class="px-4 py-3">Endpoint</th>
            <th class="px-4 py-3">Source</th>
            <th class="px-4 py-3">Status</th>
            <th class="px-4 py-3">Created</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="alert in items" :key="alert.alertInfo.alertId"
            class="border-b border-s1-border/50 hover:bg-s1-hover transition-colors"
          >
            <td class="px-4 py-3">
              <span :class="SEVERITY_COLOR[alert.ruleInfo.severity] ?? 'text-s1-muted'" class="font-semibold text-xs">
                {{ alert.ruleInfo.severity }}
              </span>
            </td>
            <td class="px-4 py-3">
              <div class="text-s1-text font-medium">{{ alert.ruleInfo.name }}</div>
              <div class="text-xs text-s1-muted truncate max-w-xs">{{ alert.ruleInfo.description }}</div>
            </td>
            <td class="px-4 py-3 text-s1-text">{{ alert.agentRealtimeInfo.agentComputerName }}</td>
            <td class="px-4 py-3">
              <div class="text-xs text-s1-muted">{{ alert.alertInfo.source }}</div>
            </td>
            <td class="px-4 py-3">
              <StatusBadge :status="alert.alertInfo.incidentStatus" type="incident" />
            </td>
            <td class="px-4 py-3 text-s1-muted text-xs">{{ alert.alertInfo.createdAt?.slice(0, 10) }}</td>
          </tr>
        </tbody>
      </table>

      <div v-if="nextCursor" class="p-4 border-t border-s1-border">
        <button @click="fetchList(false)" :disabled="loading" class="btn-ghost text-sm w-full">
          Load more
        </button>
      </div>
    </div>
  </div>
</template>
