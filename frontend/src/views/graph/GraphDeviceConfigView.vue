<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ensureGraphAuth, graphIntuneApi } from '../../api/graph'
import type { GraphDeviceConfiguration } from '../../types/graph'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const configs = ref<GraphDeviceConfiguration[]>([])

async function fetchConfigs(): Promise<void> {
  loading.value = true
  try {
    await ensureGraphAuth()
    const res = await graphIntuneApi.listConfigs({ $top: 999 })
    configs.value = res.value ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchConfigs())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="font-bold" style="color: #0078D4">Graph</span> Device Configuration
        </h1>
        <p class="text-s1-muted text-sm">Intune device configuration profiles</p>
      </div>
      <button @click="fetchConfigs()" class="btn-ghost flex items-center gap-2">
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
            <th class="table-header text-left">Description</th>
            <th class="table-header text-left">Last Modified</th>
            <th class="table-header text-left">Created</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !configs.length" :rows="8" />
          <template v-else>
            <tr v-for="config in configs" :key="config.id" class="table-row">
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ config.displayName }}</div>
              </td>
              <td class="table-cell text-sm text-s1-muted truncate max-w-[300px]">
                {{ config.description || '—' }}
              </td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(config.lastModifiedDateTime) }}</td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(config.createdDateTime) }}</td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !configs.length"
        icon="--"
        title="No configurations"
        description="No device configuration profiles available."
      />
    </div>
  </div>
</template>
