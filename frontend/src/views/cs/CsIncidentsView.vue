<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ensureCsAuth, csIncidentsApi } from '../../api/crowdstrike'
import type { CsIncident } from '../../types/crowdstrike'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const incidents = ref<CsIncident[]>([])
const total = ref(0)
const offset = ref(0)
const limit = 25

// Filters
const filterStatus = ref('')

const STATUS_MAP: Record<number, string> = {
  20: 'New',
  25: 'Reopened',
  30: 'In Progress',
  40: 'Closed',
}

function statusLabel(status: number): string {
  return STATUS_MAP[status] ?? `Status ${status}`
}

function statusBadgeClass(status: number): string {
  switch (status) {
    case 20: return 'bg-blue-500/15 text-blue-400'
    case 25: return 'bg-orange-500/15 text-orange-400'
    case 30: return 'bg-yellow-500/15 text-yellow-400'
    case 40: return 'bg-green-500/15 text-green-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function scoreBadgeClass(score: number): string {
  if (score >= 80) return 'text-red-400'
  if (score >= 60) return 'text-orange-400'
  if (score >= 40) return 'text-yellow-400'
  return 'text-s1-muted'
}

async function fetchIncidents(append = false): Promise<void> {
  loading.value = true
  try {
    await ensureCsAuth()

    const params: Record<string, unknown> = {
      offset: append ? offset.value : 0,
      limit,
    }

    if (filterStatus.value) {
      params['filter'] = `status:${filterStatus.value}`
    }

    const idsRes = await csIncidentsApi.queryIds(params)
    total.value = idsRes.meta.pagination?.total ?? idsRes.resources.length

    if (idsRes.resources.length === 0) {
      if (!append) incidents.value = []
      return
    }

    const entitiesRes = await csIncidentsApi.getEntities(idsRes.resources)

    if (append) {
      incidents.value = [...incidents.value, ...entitiesRes.resources]
    } else {
      incidents.value = entitiesRes.resources
      offset.value = 0
    }
    offset.value += idsRes.resources.length
  } finally {
    loading.value = false
  }
}

const hasMore = computed(() => offset.value < total.value)

watch(filterStatus, () => fetchIncidents())

onMounted(() => fetchIncidents())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="text-red-500 font-bold">CS</span> Incidents
        </h1>
        <p class="text-s1-muted text-sm">{{ total }} incidents total</p>
      </div>
      <button @click="fetchIncidents()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Filter bar -->
    <div class="card p-4 flex flex-wrap gap-3">
      <select v-model="filterStatus" class="select">
        <option value="">All Statuses</option>
        <option value="20">New</option>
        <option value="25">Reopened</option>
        <option value="30">In Progress</option>
        <option value="40">Closed</option>
      </select>
    </div>

    <!-- Table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Name</th>
            <th class="table-header text-left">Status</th>
            <th class="table-header text-left">Score</th>
            <th class="table-header text-left">Hosts</th>
            <th class="table-header text-left">Tactics</th>
            <th class="table-header text-left">Created</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !incidents.length" :rows="8" />
          <template v-else>
            <tr
              v-for="inc in incidents" :key="inc.incident_id"
              class="table-row"
            >
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm truncate max-w-[250px]">{{ inc.name }}</div>
                <div class="text-xs text-s1-muted truncate max-w-[250px]">{{ inc.description }}</div>
              </td>
              <td class="table-cell">
                <span
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="statusBadgeClass(inc.status)"
                >
                  {{ statusLabel(inc.status) }}
                </span>
              </td>
              <td class="table-cell">
                <span class="font-mono text-sm font-bold" :class="scoreBadgeClass(inc.fine_score)">
                  {{ inc.fine_score }}
                </span>
              </td>
              <td class="table-cell">
                <div class="text-sm text-s1-subtle">{{ inc.hosts?.length ?? 0 }} host(s)</div>
                <div v-if="inc.hosts?.length" class="text-xs text-s1-muted truncate max-w-[150px]">
                  {{ inc.hosts.map(h => h.hostname).join(', ') }}
                </div>
              </td>
              <td class="table-cell">
                <div class="flex flex-wrap gap-1">
                  <span
                    v-for="tactic in (inc.tactics ?? []).slice(0, 3)" :key="tactic"
                    class="text-xs px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 font-mono"
                  >
                    {{ tactic }}
                  </span>
                  <span v-if="(inc.tactics?.length ?? 0) > 3" class="text-xs text-s1-muted">
                    +{{ inc.tactics.length - 3 }}
                  </span>
                </div>
              </td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(inc.created) }}</td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !incidents.length"
        icon="--"
        title="No incidents found"
        description="No incidents match your current filters."
      />

      <div v-if="hasMore" class="p-4 text-center border-t border-s1-border">
        <button @click="fetchIncidents(true)" class="btn-ghost text-sm" :disabled="loading">
          Load more incidents
        </button>
      </div>
    </div>
  </div>
</template>
