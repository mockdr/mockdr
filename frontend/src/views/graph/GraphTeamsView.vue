<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ensureGraphAuth, graphTeamsApi } from '../../api/graph'
import type { GraphTeam } from '../../types/graph'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const teams = ref<GraphTeam[]>([])

function visibilityBadgeClass(visibility: string): string {
  switch (visibility.toLowerCase()) {
    case 'public': return 'bg-green-500/15 text-green-400'
    case 'private': return 'bg-yellow-500/15 text-yellow-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function fetchTeams(): Promise<void> {
  loading.value = true
  try {
    await ensureGraphAuth()
    const res = await graphTeamsApi.list({ $top: 999 })
    teams.value = res.value ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchTeams())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="font-bold" style="color: #0078D4">Graph</span> Teams
        </h1>
        <p class="text-s1-muted text-sm">Microsoft Teams</p>
      </div>
      <button @click="fetchTeams()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Loading -->
    <div v-if="loading && !teams.length" class="card p-5">
      <LoadingSkeleton :rows="4" />
    </div>

    <!-- Empty -->
    <EmptyState
      v-if="!loading && !teams.length"
      icon="--"
      title="No teams found"
      description="No Microsoft Teams available."
    />

    <!-- Card grid -->
    <div v-if="teams.length" class="grid grid-cols-3 gap-4">
      <div
        v-for="team in teams" :key="team.id"
        class="card p-5"
      >
        <div class="flex items-start justify-between mb-2">
          <h3 class="text-sm font-semibold text-s1-text truncate max-w-[70%]">{{ team.displayName }}</h3>
          <span
            class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
            :class="visibilityBadgeClass(team.visibility)"
          >
            {{ team.visibility }}
          </span>
        </div>
        <p class="text-xs text-s1-muted line-clamp-2">{{ team.description || 'No description' }}</p>
      </div>
    </div>
  </div>
</template>
