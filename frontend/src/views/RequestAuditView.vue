<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { Trash2, RefreshCw, Search } from 'lucide-vue-next'
import { systemApi } from '../api/system'
import LoadingSkeleton from '../components/shared/LoadingSkeleton.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import type { RequestLog } from '../types'

const logs = ref<RequestLog[]>([])
const loading = ref(true)
const clearing = ref(false)
const search = ref('')

const filtered = computed(() => {
  const q = search.value.toLowerCase()
  if (!q) return logs.value
  return logs.value.filter(
    (r) => r.path.toLowerCase().includes(q) || r.method.toLowerCase().includes(q) || r.token_hint.toLowerCase().includes(q),
  )
})

async function fetchLogs(): Promise<void> {
  loading.value = true
  try {
    const res = await systemApi.listRequests()
    logs.value = res.data
  } finally {
    loading.value = false
  }
}

async function clearLogs(): Promise<void> {
  clearing.value = true
  try {
    await systemApi.clearRequests()
    logs.value = []
  } finally {
    clearing.value = false
  }
}

onMounted(() => fetchLogs())

function methodColor(method: string): string {
  const MAP: Record<string, string> = {
    GET: 'bg-s1-cyan/20 text-s1-cyan',
    POST: 'bg-s1-success/20 text-s1-success',
    PUT: 'bg-s1-warning/20 text-s1-warning',
    PATCH: 'bg-s1-warning/20 text-s1-warning',
    DELETE: 'bg-s1-danger/20 text-s1-danger',
  }
  return MAP[method] ?? 'bg-s1-hover text-s1-muted'
}

function statusColor(code: number): string {
  if (code < 300) return 'text-s1-success'
  if (code < 400) return 'text-s1-cyan'
  if (code < 500) return 'text-s1-warning'
  return 'text-s1-danger'
}
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-s1-text">Request Audit Log</h1>
        <p class="text-s1-muted text-sm">{{ filtered.length }} of {{ logs.length }} requests (last 500)</p>
      </div>
      <div class="flex items-center gap-2">
        <button @click="fetchLogs" :disabled="loading" class="btn-ghost flex items-center gap-1.5 text-sm">
          <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
          Refresh
        </button>
        <button @click="clearLogs" :disabled="clearing || !logs.length" class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm text-s1-danger bg-s1-danger/10 hover:bg-s1-danger/20 transition-colors disabled:opacity-40">
          <Trash2 class="w-3.5 h-3.5" />
          Clear
        </button>
      </div>
    </div>

    <!-- Search -->
    <div class="relative">
      <Search class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-s1-muted" />
      <input
        v-model="search"
        type="text"
        placeholder="Filter by path, method, or token…"
        class="w-full pl-9 pr-4 py-2 bg-s1-card border border-s1-border rounded-lg text-s1-text text-sm placeholder-s1-muted focus:outline-none focus:border-s1-primary/60"
      />
    </div>

    <div class="card overflow-hidden">
      <div v-if="loading && !logs.length"><LoadingSkeleton :rows="12" /></div>
      <EmptyState v-else-if="!filtered.length" title="No requests" description="No API requests recorded yet — make some calls first" />

      <div v-else class="divide-y divide-s1-border/50">
        <div
          v-for="log in filtered" :key="log.id"
          class="px-4 py-3 flex items-center gap-3 hover:bg-s1-hover transition-colors text-sm font-mono"
        >
          <!-- Method -->
          <span class="px-2 py-0.5 rounded text-[11px] font-bold flex-shrink-0" :class="methodColor(log.method)">
            {{ log.method }}
          </span>

          <!-- Status -->
          <span class="w-10 text-right font-bold flex-shrink-0" :class="statusColor(log.status_code)">
            {{ log.status_code }}
          </span>

          <!-- Path -->
          <span class="flex-1 text-s1-text truncate">
            {{ log.path }}<span v-if="log.query_string" class="text-s1-muted">?{{ log.query_string }}</span>
          </span>

          <!-- Duration -->
          <span class="text-s1-muted text-xs flex-shrink-0 w-16 text-right">{{ log.duration_ms }}ms</span>

          <!-- Token -->
          <span class="text-s1-muted text-[11px] flex-shrink-0 w-24 truncate text-right" :title="log.token_hint">
            {{ log.token_hint || '—' }}
          </span>

          <!-- Timestamp -->
          <span class="text-s1-muted text-[11px] flex-shrink-0 w-44 text-right">
            {{ log.timestamp.slice(0, 19).replace('T', ' ') }}
          </span>
        </div>
      </div>
    </div>
  </div>
</template>
