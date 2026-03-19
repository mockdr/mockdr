<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ensureGraphAuth, graphAdminApi } from '../../api/graph'
import type { GraphSubscribedSku } from '../../types/graph'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const skus = ref<GraphSubscribedSku[]>([])

function usagePercent(sku: GraphSubscribedSku): number {
  const enabled = sku.prepaidUnits.enabled
  if (!enabled) return 0
  return Math.round((sku.consumedUnits / enabled) * 100)
}

function progressBarClass(pct: number): string {
  if (pct > 90) return 'bg-red-500'
  if (pct > 70) return 'bg-yellow-500'
  return 'bg-blue-500'
}

async function fetchSkus(): Promise<void> {
  loading.value = true
  try {
    await ensureGraphAuth()
    const res = await graphAdminApi.listSkus({ $top: 999 })
    skus.value = res.value ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchSkus())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="font-bold" style="color: #0078D4">Graph</span> Licenses
        </h1>
        <p class="text-s1-muted text-sm">Subscribed SKUs and license usage</p>
      </div>
      <button @click="fetchSkus()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">SKU Name</th>
            <th class="table-header text-left">Part Number</th>
            <th class="table-header text-left">Consumed / Enabled</th>
            <th class="table-header text-left">Usage</th>
            <th class="table-header text-left">Status</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !skus.length" :rows="8" />
          <template v-else>
            <tr v-for="sku in skus" :key="sku.id" class="table-row">
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ sku.skuPartNumber }}</div>
              </td>
              <td class="table-cell">
                <span class="font-mono text-xs text-s1-muted">{{ sku.skuPartNumber }}</span>
              </td>
              <td class="table-cell text-sm text-s1-subtle">
                {{ sku.consumedUnits }} / {{ sku.prepaidUnits.enabled }}
              </td>
              <td class="table-cell">
                <div class="flex items-center gap-2">
                  <div class="w-24 h-2 bg-s1-border rounded-full overflow-hidden">
                    <div
                      class="h-full rounded-full transition-all"
                      :class="progressBarClass(usagePercent(sku))"
                      :style="{ width: `${Math.min(usagePercent(sku), 100)}%` }"
                    />
                  </div>
                  <span class="text-xs text-s1-muted">{{ usagePercent(sku) }}%</span>
                </div>
              </td>
              <td class="table-cell">
                <span
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="sku.capabilityStatus === 'Enabled'
                    ? 'bg-green-500/15 text-green-400'
                    : 'bg-gray-500/15 text-gray-400'"
                >
                  {{ sku.capabilityStatus }}
                </span>
              </td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !skus.length"
        icon="--"
        title="No licenses found"
        description="No subscribed SKUs available."
      />
    </div>
  </div>
</template>
