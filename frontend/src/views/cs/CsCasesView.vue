<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ensureCsAuth, csCasesApi } from '../../api/crowdstrike'
import type { CsCase } from '../../types/crowdstrike'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const cases = ref<CsCase[]>([])

function statusBadgeClass(status: string): string {
  switch (status?.toLowerCase()) {
    case 'open': return 'bg-blue-500/15 text-blue-400'
    case 'in_progress': case 'in progress': return 'bg-yellow-500/15 text-yellow-400'
    case 'closed': return 'bg-green-500/15 text-green-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function formatDate(iso: string): string {
  if (!iso) return '--'
  return new Date(iso).toLocaleString()
}

async function fetchCases(): Promise<void> {
  loading.value = true
  try {
    await ensureCsAuth()
    const res = await csCasesApi.list()
    cases.value = res.resources ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchCases())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="text-red-500 font-bold">CS</span> Cases
        </h1>
        <p class="text-s1-muted text-sm">CrowdStrike investigation and support cases</p>
      </div>
      <button @click="fetchCases()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Summary -->
    <div class="grid grid-cols-3 gap-3">
      <div class="card p-4">
        <div class="text-xs text-s1-muted uppercase tracking-wider">Total Cases</div>
        <div class="text-2xl font-bold text-s1-text mt-1">{{ cases.length }}</div>
      </div>
      <div class="card p-4">
        <div class="text-xs text-s1-muted uppercase tracking-wider">Open</div>
        <div class="text-2xl font-bold text-blue-400 mt-1">
          {{ cases.filter(c => c.status?.toLowerCase() === 'open').length }}
        </div>
      </div>
      <div class="card p-4">
        <div class="text-xs text-s1-muted uppercase tracking-wider">Closed</div>
        <div class="text-2xl font-bold text-green-400 mt-1">
          {{ cases.filter(c => c.status?.toLowerCase() === 'closed').length }}
        </div>
      </div>
    </div>

    <!-- Table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Title</th>
            <th class="table-header text-left">Status</th>
            <th class="table-header text-left">Type</th>
            <th class="table-header text-left">Tags</th>
            <th class="table-header text-left">Detections</th>
            <th class="table-header text-left">Created</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !cases.length" :rows="8" />
          <template v-else>
            <tr v-for="cs in cases" :key="cs.id" class="table-row">
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm max-w-[300px] truncate">{{ cs.title }}</div>
                <div class="text-xs text-s1-muted font-mono">{{ cs.id?.slice(0, 8) }}...</div>
              </td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="statusBadgeClass(cs.status)">
                  {{ cs.status }}
                </span>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ cs.type || '--' }}</td>
              <td class="table-cell">
                <div class="flex flex-wrap gap-1">
                  <span v-for="tag in (cs.tags ?? []).slice(0, 3)" :key="tag"
                    class="px-1.5 py-0.5 rounded text-[10px] bg-s1-hover text-s1-subtle">
                    {{ tag }}
                  </span>
                </div>
              </td>
              <td class="table-cell text-sm text-s1-text">{{ cs.detections?.length ?? 0 }}</td>
              <td class="table-cell text-xs text-s1-muted">{{ formatDate(cs.created_time) }}</td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !cases.length"
        icon="--"
        title="No cases"
        description="No investigation cases found."
      />
    </div>
  </div>
</template>
