<script setup lang="ts">
import { ref, onUnmounted } from 'vue'
import { dvApi } from '../api/misc'
import { Play, X, Search } from 'lucide-vue-next'
import type { DvEvent } from '../types'

const queryText = ref('')
const fromDate = ref('')
const toDate = ref('')
const running = ref(false)
const progress = ref(0)
const events = ref<DvEvent[]>([])
const total = ref(0)
const nextCursor = ref<string | null>(null)
const currentQueryId = ref<string | null>(null)
const pollError = ref('')
let pollInterval: ReturnType<typeof setInterval> | null = null

onUnmounted(() => { if (pollInterval) clearInterval(pollInterval) })

async function runQuery(): Promise<void> {
  if (!queryText.value.trim()) return
  events.value = []
  total.value = 0
  nextCursor.value = null
  running.value = true
  progress.value = 0

  const body = {
    query: queryText.value,
    fromDate: fromDate.value || new Date(Date.now() - 86400000).toISOString(),
    toDate: toDate.value || new Date().toISOString(),
  }
  const res = await dvApi.initQuery(body)
  currentQueryId.value = res.data.queryId

  pollInterval = setInterval(async () => {
    try {
      const status = await dvApi.queryStatus(currentQueryId.value!)
      progress.value = status.data.progressPercentage ?? progress.value
      if (status.data.responseState === 'FINISHED') {
        clearInterval(pollInterval ?? undefined)
        pollInterval = null
        running.value = false
        await loadEvents(true)
      }
    } catch (e: unknown) {
      clearInterval(pollInterval ?? undefined)
      pollInterval = null
      running.value = false
      pollError.value = e instanceof Error ? e.message : 'Polling failed'
    }
  }, 500)
}

async function cancelQuery(): Promise<void> {
  if (!currentQueryId.value) return
  clearInterval(pollInterval ?? undefined)
  pollInterval = null
  await dvApi.cancel(currentQueryId.value)
  running.value = false
}

async function loadEvents(reset = true): Promise<void> {
  const params: Record<string, unknown> = { limit: 50 }
  if (!reset && nextCursor.value) params['cursor'] = nextCursor.value
  const res = await dvApi.events(currentQueryId.value!, params)
  events.value = reset ? res.data : [...events.value, ...res.data]
  total.value = res.pagination?.totalItems ?? events.value.length
  nextCursor.value = res.pagination?.nextCursor
}

const EVENT_TYPE_COLOR: Record<string, string> = {
  Process: 'text-s1-cyan',
  File: 'text-s1-warning',
  Network: 'text-s1-success',
  Registry: 'text-purple-400',
  DNS: 'text-pink-400',
}
</script>

<template>
  <div class="space-y-4">
    <div>
      <h1 class="text-xl font-bold text-s1-text">Deep Visibility</h1>
      <p class="text-s1-muted text-sm">Query endpoint telemetry events</p>
    </div>

    <!-- Query input -->
    <div class="card p-4 space-y-3">
      <textarea
        v-model="queryText"
        class="input w-full font-mono text-sm resize-none"
        rows="3"
        placeholder='EventType = "Process" AND TgtFilePath ContainsCIS "powershell"'
      />
      <div class="flex gap-3 items-end">
        <div class="flex-1">
          <label class="text-xs text-s1-muted mb-1 block">From</label>
          <input v-model="fromDate" type="datetime-local" class="input w-full text-sm" />
        </div>
        <div class="flex-1">
          <label class="text-xs text-s1-muted mb-1 block">To</label>
          <input v-model="toDate" type="datetime-local" class="input w-full text-sm" />
        </div>
        <button v-if="!running" @click="runQuery" class="btn-primary flex items-center gap-2">
          <Play class="w-4 h-4" /> Run Query
        </button>
        <button v-else @click="cancelQuery" class="btn-ghost flex items-center gap-2 text-s1-danger">
          <X class="w-4 h-4" /> Cancel
        </button>
      </div>

      <!-- Progress -->
      <div v-if="running" class="space-y-1.5">
        <div class="flex justify-between text-xs text-s1-muted">
          <span>Running query...</span>
          <span>{{ progress }}%</span>
        </div>
        <div class="h-1.5 bg-s1-border rounded-full overflow-hidden">
          <div
            class="h-full bg-s1-primary transition-all duration-300 rounded-full"
            :style="{ width: `${progress}%` }"
          />
        </div>
      </div>
    </div>

    <div v-if="pollError" class="error-banner">{{ pollError }}</div>

    <!-- Results -->
    <div v-if="events.length" class="card overflow-hidden">
      <div class="px-4 py-3 border-b border-s1-border flex items-center gap-2">
        <Search class="w-4 h-4 text-s1-muted" />
        <span class="text-sm text-s1-text font-medium">{{ total }} events</span>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-xs">
          <thead class="border-b border-s1-border">
            <tr class="text-left text-s1-muted uppercase tracking-wide">
              <th class="px-4 py-2.5">Type</th>
              <th class="px-4 py-2.5">Time</th>
              <th class="px-4 py-2.5">Endpoint</th>
              <th class="px-4 py-2.5">Process</th>
              <th class="px-4 py-2.5">User</th>
              <th class="px-4 py-2.5">Details</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="(ev, i) in events" :key="i"
              class="border-b border-s1-border/40 hover:bg-s1-hover transition-colors"
            >
              <td class="px-4 py-2">
                <span :class="EVENT_TYPE_COLOR[ev.eventType] ?? 'text-s1-muted'" class="font-semibold">
                  {{ ev.eventType }}
                </span>
              </td>
              <td class="px-4 py-2 text-s1-muted font-mono whitespace-nowrap">
                {{ ev.eventTime?.slice(0, 19).replace('T', ' ') }}
              </td>
              <td class="px-4 py-2 text-s1-text">{{ ev.agentName }}</td>
              <td class="px-4 py-2 text-s1-muted font-mono">{{ ev.processName }}</td>
              <td class="px-4 py-2 text-s1-muted">{{ ev.user }}</td>
              <td class="px-4 py-2 text-s1-muted font-mono truncate max-w-xs">{{ ev.details }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="nextCursor" class="p-3 border-t border-s1-border">
        <button @click="loadEvents(false)" class="btn-ghost text-sm w-full">Load more</button>
      </div>
    </div>

    <div v-else-if="!running" class="card p-12 text-center text-s1-muted">
      <Search class="w-10 h-10 mx-auto mb-3 opacity-30" />
      <p class="text-sm">Enter a query and click Run to search endpoint telemetry</p>
    </div>
  </div>
</template>
