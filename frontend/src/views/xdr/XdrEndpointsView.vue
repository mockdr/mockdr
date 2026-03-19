<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { RefreshCw, Shield, ShieldOff } from 'lucide-vue-next'
import { xdrEndpointsApi } from '../../api/cortex'
import type { XdrEndpoint } from '../../types/cortex'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const router = useRouter()
const loading = ref(false)
const endpoints = ref<XdrEndpoint[]>([])
const totalCount = ref(0)

const filterOs = ref('')
const filterStatus = ref('')

const selected = ref<Set<string>>(new Set())

const allSelected = computed(() =>
  filteredEndpoints.value.length > 0 && filteredEndpoints.value.every(ep => selected.value.has(ep.endpoint_id)),
)

function toggleAll(): void {
  if (allSelected.value) {
    selected.value = new Set()
  } else {
    selected.value = new Set(filteredEndpoints.value.map(ep => ep.endpoint_id))
  }
}

function toggleSelect(id: string): void {
  const next = new Set(selected.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  selected.value = next
}

function relativeTime(epochMs: number): string {
  if (!epochMs) return '--'
  const diff = Math.floor((Date.now() - epochMs) / 1000)
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

function statusBadgeClass(status: string): string {
  switch ((status ?? '').toLowerCase()) {
    case 'connected': return 'bg-green-500/15 text-green-400'
    case 'disconnected': return 'bg-red-500/15 text-red-400'
    case 'lost': return 'bg-gray-500/15 text-gray-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function isolationBadgeClass(isolation: string): string {
  switch ((isolation ?? '').toLowerCase()) {
    case 'isolated': return 'bg-red-500/15 text-red-400'
    case 'unisolated':
    case 'not_isolated': return 'bg-green-500/15 text-green-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

const filteredEndpoints = computed(() => {
  let result = endpoints.value
  if (filterOs.value) {
    result = result.filter(ep => (ep.os_type ?? '').toLowerCase() === filterOs.value)
  }
  if (filterStatus.value) {
    result = result.filter(ep => (ep.endpoint_status ?? '').toLowerCase() === filterStatus.value)
  }
  return result
})

async function fetchEndpoints(): Promise<void> {
  loading.value = true
  try {
    const res = await xdrEndpointsApi.list()
    endpoints.value = res.reply?.endpoints ?? []
    totalCount.value = res.reply?.total_count ?? endpoints.value.length
  } finally {
    loading.value = false
  }
}

async function performAction(action: 'isolate' | 'unisolate'): Promise<void> {
  if (selected.value.size === 0) return
  loading.value = true
  try {
    const ids = [...selected.value]
    for (const epId of ids) {
      if (action === 'isolate') {
        await xdrEndpointsApi.isolate(epId)
      } else {
        await xdrEndpointsApi.unisolate(epId)
      }
    }
    selected.value = new Set()
    await fetchEndpoints()
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
          <span class="text-orange-500 font-bold">XDR</span> Endpoints
        </h1>
        <p class="text-s1-muted text-sm">Cortex XDR endpoint management</p>
      </div>
      <button @click="fetchEndpoints()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Filter bar -->
    <div class="card p-4 flex flex-wrap gap-3">
      <select v-model="filterOs" class="select">
        <option value="">All OS Types</option>
        <option value="windows">Windows</option>
        <option value="linux">Linux</option>
        <option value="macos">macOS</option>
      </select>
      <select v-model="filterStatus" class="select">
        <option value="">All Statuses</option>
        <option value="connected">Connected</option>
        <option value="disconnected">Disconnected</option>
        <option value="lost">Lost</option>
      </select>
      <div class="ml-auto text-xs text-s1-muted self-center">
        {{ filteredEndpoints.length }} of {{ totalCount }} endpoints
      </div>
    </div>

    <!-- Bulk action bar -->
    <Transition name="slide-down">
      <div v-if="selected.size > 0" class="card px-4 py-3 flex items-center gap-3 border-orange-500/40">
        <span class="text-sm text-s1-text font-medium">{{ selected.size }} selected</span>
        <div class="h-4 w-px bg-s1-border"></div>
        <button @click="performAction('isolate')" class="btn-ghost flex items-center gap-1.5 text-xs">
          <Shield class="w-3.5 h-3.5" /> Isolate
        </button>
        <button @click="performAction('unisolate')" class="btn-ghost flex items-center gap-1.5 text-xs">
          <ShieldOff class="w-3.5 h-3.5" /> Unisolate
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
                class="rounded border-s1-border bg-s1-bg accent-orange-500" />
            </th>
            <th class="table-header text-left">Endpoint Name</th>
            <th class="table-header text-left">OS Type</th>
            <th class="table-header text-left">Status</th>
            <th class="table-header text-left">IP</th>
            <th class="table-header text-left">Isolation</th>
            <th class="table-header text-left">Last Seen</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !endpoints.length" :rows="8" />
          <template v-else>
            <tr
              v-for="ep in filteredEndpoints" :key="ep.endpoint_id"
              class="table-row"
              :class="selected.has(ep.endpoint_id) ? 'bg-orange-500/5' : ''"
              @click="router.push(`/cortex-xdr/endpoints/${ep.endpoint_id}`)"
            >
              <td class="table-cell" @click.stop>
                <input type="checkbox" :checked="selected.has(ep.endpoint_id)"
                  @change="toggleSelect(ep.endpoint_id)"
                  class="rounded border-s1-border bg-s1-bg accent-orange-500" />
              </td>
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ ep.endpoint_name }}</div>
                <div class="text-xs text-s1-muted">{{ ep.domain || '' }}</div>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ ep.os_type }}</td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="statusBadgeClass(ep.endpoint_status)">
                  {{ ep.endpoint_status }}
                </span>
              </td>
              <td class="table-cell text-sm text-s1-subtle">
                {{ Array.isArray(ep.ip) ? ep.ip[0] : ep.ip || '--' }}
              </td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="isolationBadgeClass(ep.is_isolated)">
                  {{ ep.is_isolated || 'N/A' }}
                </span>
              </td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(ep.last_seen) }}</td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !filteredEndpoints.length"
        icon="--"
        title="No endpoints found"
        description="No endpoints match your current filters."
      />
    </div>
  </div>
</template>

<style scoped>
.slide-down-enter-active, .slide-down-leave-active { transition: all 0.2s; }
.slide-down-enter-from, .slide-down-leave-to { opacity: 0; transform: translateY(-8px); }
</style>
