<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ensureGraphAuth, graphIdentityApi } from '../../api/graph'
import type { GraphAuditLog } from '../../types/graph'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const logs = ref<GraphAuditLog[]>([])

function resultBadgeClass(result: string): string {
  return result === 'success'
    ? 'bg-green-500/15 text-green-400'
    : 'bg-red-500/15 text-red-400'
}

function initiatedByName(initiatedBy: Record<string, unknown>): string {
  const user = initiatedBy?.user as Record<string, unknown> | undefined
  if (user?.displayName) return user.displayName as string
  const app = initiatedBy?.app as Record<string, unknown> | undefined
  if (app?.displayName) return app.displayName as string
  return '—'
}

async function fetchLogs(): Promise<void> {
  loading.value = true
  try {
    await ensureGraphAuth()
    const res = await graphIdentityApi.listAuditLogs({ $top: 50 })
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
          <span class="font-bold" style="color: #0078D4">Graph</span> Audit Logs
        </h1>
        <p class="text-s1-muted text-sm">Entra ID directory audit logs</p>
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
            <th class="table-header text-left">Activity</th>
            <th class="table-header text-left">Category</th>
            <th class="table-header text-left">Result</th>
            <th class="table-header text-left">Initiated By</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !logs.length" :rows="8" />
          <template v-else>
            <tr v-for="log in logs" :key="log.id" class="table-row">
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(log.activityDateTime) }}</td>
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ log.activityDisplayName }}</div>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ log.category }}</td>
              <td class="table-cell">
                <span
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="resultBadgeClass(log.result)"
                >
                  {{ log.result }}
                </span>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ initiatedByName(log.initiatedBy) }}</td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !logs.length"
        icon="--"
        title="No audit logs"
        description="No directory audit log entries available."
      />
    </div>
  </div>
</template>
