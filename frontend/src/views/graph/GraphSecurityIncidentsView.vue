<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ensureGraphAuth, graphSecurityApi } from '../../api/graph'
import type { GraphSecurityIncident } from '../../types/graph'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const incidents = ref<GraphSecurityIncident[]>([])

function severityBadgeClass(severity: string): string {
  switch (severity) {
    case 'high': return 'bg-red-500/15 text-red-400'
    case 'medium': return 'bg-yellow-500/15 text-yellow-400'
    case 'low': return 'bg-blue-500/15 text-blue-400'
    case 'informational': return 'bg-gray-500/15 text-gray-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function statusBadgeClass(status: string): string {
  switch (status) {
    case 'active': return 'bg-red-500/15 text-red-400'
    case 'inProgress': return 'bg-yellow-500/15 text-yellow-400'
    case 'resolved': return 'bg-green-500/15 text-green-400'
    case 'redirected': return 'bg-gray-500/15 text-gray-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function fetchIncidents(): Promise<void> {
  loading.value = true
  try {
    await ensureGraphAuth()
    const res = await graphSecurityApi.listIncidents({ $top: 999 })
    incidents.value = res.value ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchIncidents())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="font-bold" style="color: #0078D4">Graph</span> Security Incidents
        </h1>
        <p class="text-s1-muted text-sm">Microsoft 365 Defender incidents</p>
      </div>
      <button @click="fetchIncidents()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Name</th>
            <th class="table-header text-left">Severity</th>
            <th class="table-header text-left">Status</th>
            <th class="table-header text-left">Alerts Count</th>
            <th class="table-header text-left">Created</th>
            <th class="table-header text-left">Assigned To</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !incidents.length" :rows="8" />
          <template v-else>
            <tr v-for="incident in incidents" :key="incident.id" class="table-row">
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm truncate max-w-[250px]">{{ incident.displayName }}</div>
              </td>
              <td class="table-cell">
                <span
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="severityBadgeClass(incident.severity)"
                >
                  {{ incident.severity }}
                </span>
              </td>
              <td class="table-cell">
                <span
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="statusBadgeClass(incident.status)"
                >
                  {{ incident.status }}
                </span>
              </td>
              <td class="table-cell text-sm text-s1-subtle">
                {{ incident.alert_ids?.length ?? '—' }}
              </td>
              <td class="table-cell text-xs text-s1-muted">
                {{ relativeTime(incident.createdDateTime) }}
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ incident.assignedTo ?? 'Unassigned' }}</td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !incidents.length"
        icon="--"
        title="No incidents found"
        description="No security incidents available."
      />
    </div>
  </div>
</template>
