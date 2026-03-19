<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { RefreshCw, Shield, ShieldOff } from 'lucide-vue-next'
import { esEndpointsApi } from '../../api/elastic'
import type { EsEndpoint } from '../../types/elastic'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const endpoints = ref<EsEndpoint[]>([])
const total = ref(0)
const page = ref(1)
const perPage = 25

// Selection
const selected = ref<Set<string>>(new Set())

const allSelected = computed(() =>
  endpoints.value.length > 0 && endpoints.value.every(ep => selected.value.has(ep.agent_id)),
)

function toggleAll(): void {
  if (allSelected.value) {
    selected.value = new Set()
  } else {
    selected.value = new Set(endpoints.value.map(ep => ep.agent_id))
  }
}

function toggleSelect(id: string): void {
  const next = new Set(selected.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  selected.value = next
}

function statusBadgeClass(status: string): string {
  switch (status) {
    case 'online': return 'bg-green-500/15 text-green-400'
    case 'offline': return 'bg-gray-500/15 text-gray-400'
    case 'enrolling': return 'bg-yellow-500/15 text-yellow-400'
    case 'unenrolling': return 'bg-orange-500/15 text-orange-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function isolationBadgeClass(status: string): string {
  switch (status) {
    case 'isolated': return 'bg-red-500/15 text-red-400'
    case 'normal': return 'bg-green-500/15 text-green-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function fetchEndpoints(p = 1): Promise<void> {
  loading.value = true
  page.value = p
  try {
    const res = await esEndpointsApi.list({ page: p, per_page: perPage })
    endpoints.value = res.data ?? []
    total.value = res.total ?? endpoints.value.length
  } finally {
    loading.value = false
  }
}

const hasPrev = computed(() => page.value > 1)
const hasNext = computed(() => page.value * perPage < total.value)

async function performAction(action: 'isolate' | 'unisolate'): Promise<void> {
  if (selected.value.size === 0) return
  loading.value = true
  try {
    const ids = [...selected.value]
    if (action === 'isolate') {
      await esEndpointsApi.isolate(ids, 'Isolated from UI')
    } else {
      await esEndpointsApi.unisolate(ids, 'Released from UI')
    }
    selected.value = new Set()
    await fetchEndpoints(page.value)
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchEndpoints())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="text-purple-500 font-bold">ES</span> Endpoints
        </h1>
        <p class="text-s1-muted text-sm">{{ total }} endpoints total</p>
      </div>
      <button @click="fetchEndpoints(page)" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Bulk action bar -->
    <Transition name="slide-down">
      <div v-if="selected.size > 0" class="card px-4 py-3 flex items-center gap-3 border-purple-500/40">
        <span class="text-sm text-s1-text font-medium">{{ selected.size }} selected</span>
        <div class="h-4 w-px bg-s1-border"></div>
        <button @click="performAction('isolate')" class="btn-ghost flex items-center gap-1.5 text-xs">
          <Shield class="w-3.5 h-3.5" /> Isolate
        </button>
        <button @click="performAction('unisolate')" class="btn-ghost flex items-center gap-1.5 text-xs">
          <ShieldOff class="w-3.5 h-3.5" /> Release
        </button>
      </div>
    </Transition>

    <!-- Table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header w-10">
              <input type="checkbox" :checked="allSelected" @change="toggleAll"
                class="rounded border-s1-border bg-s1-bg accent-purple-500" />
            </th>
            <th class="table-header text-left">Hostname</th>
            <th class="table-header text-left">OS</th>
            <th class="table-header text-left">Agent Status</th>
            <th class="table-header text-left">Isolation</th>
            <th class="table-header text-left">Agent Version</th>
            <th class="table-header text-left">Policy</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !endpoints.length" :rows="8" />
          <template v-else>
            <tr
              v-for="ep in endpoints" :key="ep.agent_id"
              class="table-row"
              :class="selected.has(ep.agent_id) ? 'bg-purple-500/5' : ''"
            >
              <td class="table-cell" @click.stop>
                <input type="checkbox" :checked="selected.has(ep.agent_id)"
                  @change="toggleSelect(ep.agent_id)"
                  class="rounded border-s1-border bg-s1-bg accent-purple-500" />
              </td>
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ ep.hostname }}</div>
                <div class="text-xs text-s1-muted">{{ ep.ip_address }}</div>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ ep.os }}</td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="statusBadgeClass(ep.agent_status)">
                  {{ ep.agent_status }}
                </span>
              </td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="isolationBadgeClass(ep.isolation_status)">
                  {{ ep.isolation_status }}
                </span>
              </td>
              <td class="table-cell">
                <span class="font-mono text-xs text-s1-muted">{{ ep.agent_version }}</span>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ ep.policy_name }}</td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !endpoints.length"
        icon="--"
        title="No endpoints found"
        description="No Elastic endpoints are enrolled."
      />

      <!-- Pagination -->
      <div v-if="endpoints.length > 0" class="p-4 flex items-center justify-between border-t border-s1-border">
        <button @click="fetchEndpoints(page - 1)" class="btn-ghost text-sm" :disabled="!hasPrev || loading">
          Previous
        </button>
        <span class="text-xs text-s1-muted">
          Page {{ page }} of {{ Math.ceil(total / perPage) }}
        </span>
        <button @click="fetchEndpoints(page + 1)" class="btn-ghost text-sm" :disabled="!hasNext || loading">
          Next
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.slide-down-enter-active, .slide-down-leave-active { transition: all 0.2s; }
.slide-down-enter-from, .slide-down-leave-to { opacity: 0; transform: translateY(-8px); }
</style>
