<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ensureGraphAuth, graphAdminApi } from '../../api/graph'
import type { GraphAttackSimulation } from '../../types/graph'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const simulations = ref<GraphAttackSimulation[]>([])

function statusBadgeClass(status: string): string {
  switch (status) {
    case 'succeeded': return 'bg-green-500/15 text-green-400'
    case 'completed': return 'bg-blue-500/15 text-blue-400'
    case 'inProgress': return 'bg-yellow-500/15 text-yellow-400'
    case 'failed': return 'bg-red-500/15 text-red-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function fetchSimulations(): Promise<void> {
  loading.value = true
  try {
    await ensureGraphAuth()
    const res = await graphAdminApi.listSimulations({ $top: 999 })
    simulations.value = res.value ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchSimulations())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="font-bold" style="color: #0078D4">Graph</span> Attack Simulation
        </h1>
        <p class="text-s1-muted text-sm">Attack simulation training campaigns</p>
      </div>
      <button @click="fetchSimulations()" class="btn-ghost flex items-center gap-2">
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
            <th class="table-header text-left">Status</th>
            <th class="table-header text-left">Attack Type</th>
            <th class="table-header text-left">Launch Date</th>
            <th class="table-header text-left">Compromised Rate</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !simulations.length" :rows="8" />
          <template v-else>
            <tr v-for="sim in simulations" :key="sim.id" class="table-row">
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ sim.displayName }}</div>
              </td>
              <td class="table-cell">
                <span
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="statusBadgeClass(sim.status)"
                >
                  {{ sim.status }}
                </span>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ sim.attackType }}</td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(sim.launchDateTime) }}</td>
              <td class="table-cell text-sm text-s1-subtle">
                {{ sim.report?.compromisedRate != null
                  ? `${(sim.report.compromisedRate * 100).toFixed(1)}%`
                  : '—' }}
              </td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !simulations.length"
        icon="--"
        title="No simulations"
        description="No attack simulation campaigns found."
      />
    </div>
  </div>
</template>
