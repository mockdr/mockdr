<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { ShieldAlert, RefreshCw } from 'lucide-vue-next'
import { splunkNotableApi } from '../../api/splunk'
import type { SplunkNotable } from '../../types/splunk'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

const loading = ref(true)
const error = ref('')
const notables = ref<SplunkNotable[]>([])
const statusFilter = ref('')
const severityFilter = ref('')

const filtered = computed(() => {
  let list = notables.value
  if (statusFilter.value) list = list.filter(n => n.status === statusFilter.value)
  if (severityFilter.value) list = list.filter(n => n.severity === severityFilter.value)
  return list
})

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
  return { '1': 'New', '2': 'In Progress', '3': 'Pending', '4': 'Resolved', '5': 'Closed' }[status] ?? status
}

function formatTime(ts: string): string {
  if (!ts) return ''
  return new Date(parseFloat(ts) * 1000).toLocaleString()
}

async function fetchNotables(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    notables.value = await splunkNotableApi.list()
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : 'Failed to fetch notables'
  } finally {
    loading.value = false
  }
}

async function updateStatus(eventId: string, newStatus: string): Promise<void> {
  try {
    await splunkNotableApi.update(eventId, { status: newStatus })
    await fetchNotables()
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : 'Failed to update notable status'
  }
}

onMounted(fetchNotables)
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <ShieldAlert class="w-5 h-5 text-red-400" />
          Notable Events
        </h1>
        <p class="text-s1-muted text-sm">Splunk Enterprise Security notable events from all EDR vendors</p>
      </div>
      <button @click="fetchNotables()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Filters -->
    <div class="flex gap-3">
      <select v-model="statusFilter" class="bg-s1-input border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text">
        <option value="">All Statuses</option>
        <option value="1">New</option>
        <option value="2">In Progress</option>
        <option value="3">Pending</option>
        <option value="4">Resolved</option>
        <option value="5">Closed</option>
      </select>
      <select v-model="severityFilter" class="bg-s1-input border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text">
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
    </div>

    <div v-if="error" class="card p-4 border-red-500/40 bg-red-500/10 text-red-400 text-sm">{{ error }}</div>

    <!-- Table -->
    <div class="card">
      <LoadingSkeleton v-if="loading" :rows="8" />
      <div v-else class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-s1-border">
              <th class="px-4 py-3 text-left text-xs font-medium text-s1-muted uppercase">Rule Name</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-s1-muted uppercase">Severity</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-s1-muted uppercase">Status</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-s1-muted uppercase">Dest</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-s1-muted uppercase">Owner</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-s1-muted uppercase">Time</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-s1-muted uppercase">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-s1-border">
            <tr v-for="n in filtered" :key="n.event_id" class="hover:bg-s1-hover">
              <td class="px-4 py-3">
                <RouterLink :to="`/splunk/notables/${n.event_id}`" class="text-green-400 hover:underline">
                  {{ n.rule_name }}
                </RouterLink>
              </td>
              <td class="px-4 py-3">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium" :class="severityBadgeClass(n.severity)">
                  {{ n.severity }}
                </span>
              </td>
              <td class="px-4 py-3 text-s1-text">{{ statusLabel(n.status) }}</td>
              <td class="px-4 py-3 text-s1-text truncate max-w-[150px]">{{ n.dest }}</td>
              <td class="px-4 py-3 text-s1-text">{{ n.owner }}</td>
              <td class="px-4 py-3 text-s1-muted text-xs">{{ formatTime(n.time) }}</td>
              <td class="px-4 py-3">
                <select
                  :value="n.status"
                  @change="updateStatus(n.event_id, ($event.target as HTMLSelectElement).value)"
                  class="bg-s1-input border border-s1-border rounded px-2 py-1 text-xs text-s1-text"
                >
                  <option value="1">New</option>
                  <option value="2">In Progress</option>
                  <option value="3">Pending</option>
                  <option value="4">Resolved</option>
                  <option value="5">Closed</option>
                </select>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="!loading && !filtered.length" class="py-8 text-center text-s1-muted text-sm">
        No notable events match the current filters
      </div>
    </div>
  </div>
</template>
