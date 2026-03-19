<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ensureGraphAuth, graphIdentityApi } from '../../api/graph'
import type { GraphSignInLog } from '../../types/graph'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const logs = ref<GraphSignInLog[]>([])

function statusBadgeClass(errorCode: number): string {
  return errorCode === 0
    ? 'bg-green-500/15 text-green-400'
    : 'bg-red-500/15 text-red-400'
}

async function fetchLogs(): Promise<void> {
  loading.value = true
  try {
    await ensureGraphAuth()
    const res = await graphIdentityApi.listSignInLogs({ $top: 50 })
    logs.value = res.value ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchLogs())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="font-bold" style="color: #0078D4">Graph</span> Sign-In Logs
        </h1>
        <p class="text-s1-muted text-sm">Entra ID sign-in activity</p>
      </div>
      <button @click="fetchLogs()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Time</th>
            <th class="table-header text-left">User</th>
            <th class="table-header text-left">Application</th>
            <th class="table-header text-left">IP Address</th>
            <th class="table-header text-left">Status</th>
            <th class="table-header text-left">Location</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !logs.length" :rows="8" />
          <template v-else>
            <tr v-for="log in logs" :key="log.id" class="table-row">
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(log.createdDateTime) }}</td>
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ log.userDisplayName }}</div>
                <div class="font-mono text-xs text-s1-muted">{{ log.userPrincipalName }}</div>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ log.appDisplayName }}</td>
              <td class="table-cell">
                <span class="font-mono text-xs text-s1-muted">{{ log.ipAddress }}</span>
              </td>
              <td class="table-cell">
                <span
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="statusBadgeClass(log.status.errorCode)"
                >
                  {{ log.status.errorCode === 0 ? 'Success' : 'Failure' }}
                </span>
              </td>
              <td class="table-cell text-xs text-s1-muted">
                {{ [log.location?.city, log.location?.countryOrRegion].filter(Boolean).join(', ') || '—' }}
              </td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !logs.length"
        icon="--"
        title="No sign-in logs"
        description="No sign-in log entries available."
      />
    </div>
  </div>
</template>
