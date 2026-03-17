<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { sentinelWatchlistApi } from '../../api/sentinel'
import type { ArmResource, SentinelWatchlistProps } from '../../types/sentinel'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const watchlists = ref<ArmResource<SentinelWatchlistProps>[]>([])

let timer: ReturnType<typeof setInterval>

async function fetchWatchlists(): Promise<void> {
  loading.value = true
  try {
    const res = await sentinelWatchlistApi.list()
    watchlists.value = res.value ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  fetchWatchlists()
  timer = setInterval(fetchWatchlists, 30000)
})

onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="text-green-600 font-bold">SNTL</span> Watchlists
        </h1>
        <p class="text-s1-muted text-sm">Microsoft Sentinel watchlist management</p>
      </div>
      <button @click="fetchWatchlists()" class="btn-ghost flex items-center gap-2">
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
            <th class="table-header text-left">Items Count</th>
            <th class="table-header text-left">Search Key</th>
            <th class="table-header text-left">Created</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !watchlists.length" :rows="8" />
          <template v-else>
            <tr
              v-for="wl in watchlists" :key="wl.name"
              class="table-row"
            >
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ wl.properties.displayName }}</div>
                <div class="text-xs text-s1-muted">{{ wl.properties.provider }}</div>
              </td>
              <td class="table-cell text-sm text-s1-subtle truncate max-w-[250px]">
                {{ wl.properties.description || '--' }}
              </td>
              <td class="table-cell text-sm text-s1-text font-mono">
                {{ wl.properties.watchlistItemsCount }}
              </td>
              <td class="table-cell text-sm text-s1-subtle font-mono">
                {{ wl.properties.itemsSearchKey }}
              </td>
              <td class="table-cell text-xs text-s1-muted">
                {{ relativeTime(wl.properties.created) }}
              </td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !watchlists.length"
        icon="--"
        title="No watchlists found"
        description="No watchlists are currently configured."
      />
    </div>
  </div>
</template>
