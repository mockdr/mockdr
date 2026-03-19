<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ensureGraphAuth, graphGroupsApi } from '../../api/graph'
import type { GraphGroup } from '../../types/graph'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const groups = ref<GraphGroup[]>([])

function groupType(group: GraphGroup): string {
  if (group.groupTypes.includes('Unified')) return 'Microsoft 365'
  if (group.groupTypes.includes('DynamicMembership')) return 'Dynamic'
  if (group.securityEnabled) return 'Security'
  return 'Distribution'
}

function groupTypeBadgeClass(type: string): string {
  switch (type) {
    case 'Microsoft 365': return 'bg-blue-500/15 text-blue-400'
    case 'Security': return 'bg-green-500/15 text-green-400'
    case 'Dynamic': return 'bg-yellow-500/15 text-yellow-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function fetchGroups(): Promise<void> {
  loading.value = true
  try {
    await ensureGraphAuth()
    const res = await graphGroupsApi.list({ $top: 999 })
    groups.value = res.value ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchGroups())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="font-bold" style="color: #0078D4">Graph</span> Groups
        </h1>
        <p class="text-s1-muted text-sm">Entra ID groups</p>
      </div>
      <button @click="fetchGroups()" class="btn-ghost flex items-center gap-2">
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
            <th class="table-header text-left">Type</th>
            <th class="table-header text-left">Members Count</th>
            <th class="table-header text-left">Description</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !groups.length" :rows="8" />
          <template v-else>
            <tr v-for="group in groups" :key="group.id" class="table-row">
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ group.displayName }}</div>
              </td>
              <td class="table-cell">
                <span
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="groupTypeBadgeClass(groupType(group))"
                >
                  {{ groupType(group) }}
                </span>
              </td>
              <td class="table-cell text-sm text-s1-subtle">—</td>
              <td class="table-cell text-sm text-s1-muted truncate max-w-[300px]">
                {{ group.description || '—' }}
              </td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !groups.length"
        icon="--"
        title="No groups found"
        description="No Entra ID groups available."
      />
    </div>
  </div>
</template>
