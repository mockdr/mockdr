<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { activitiesApi } from '../api/misc'
import LoadingSkeleton from '../components/shared/LoadingSkeleton.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import type { Activity } from '../types'

const items = ref<Activity[]>([])
const total = ref(0)
const nextCursor = ref<string | null>(null)
const loading = ref(true)

async function fetchList(reset = true): Promise<void> {
  if (reset) { items.value = []; nextCursor.value = null }
  loading.value = true
  try {
    const params: Record<string, unknown> = { limit: 50 }
    if (nextCursor.value) params['cursor'] = nextCursor.value
    const res = await activitiesApi.list(params)
    items.value = reset ? res.data : [...items.value, ...res.data]
    total.value = res.pagination?.totalItems ?? items.value.length
    nextCursor.value = res.pagination?.nextCursor ?? null
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchList())

const TYPE_COLOR: Record<number, string> = {
  1001: 'text-s1-muted',    // agent registered
  2001: 'text-s1-danger',   // threat detected
  2002: 'text-s1-warning',  // threat mitigated
  3001: 'text-s1-success',  // agent connected
  3002: 'text-s1-muted',    // agent disconnected
  4001: 'text-s1-cyan',     // user login
}

function typeColor(activityType: number): string {
  return TYPE_COLOR[activityType] ?? 'text-s1-muted'
}
</script>

<template>
  <div class="space-y-4">
    <div>
      <h1 class="text-xl font-bold text-s1-text">Activity Log</h1>
      <p class="text-s1-muted text-sm">{{ total }} total events</p>
    </div>

    <div class="card overflow-hidden">
      <div v-if="loading && !items.length"><LoadingSkeleton :rows="10" /></div>
      <EmptyState v-else-if="!items.length" title="No activity" description="No activity recorded yet" />

      <div v-else class="divide-y divide-s1-border/50">
        <div
          v-for="act in items" :key="act.id"
          class="px-5 py-3.5 flex items-start gap-4 hover:bg-s1-hover transition-colors"
        >
          <div class="flex-shrink-0 mt-0.5">
            <div class="w-1.5 h-1.5 rounded-full mt-2" :class="typeColor(act.activityType).replace('text-', 'bg-')" />
          </div>
          <div class="flex-1 min-w-0">
            <div class="text-s1-text text-sm">{{ act.description }}</div>
            <div class="flex items-center gap-3 mt-0.5">
              <span v-if="act.agentComputerName" class="text-xs text-s1-muted">{{ act.agentComputerName }}</span>
              <span v-if="act.primaryDescription" class="text-xs text-s1-cyan">{{ act.primaryDescription }}</span>
            </div>
          </div>
          <div class="flex-shrink-0 text-right">
            <div class="text-xs text-s1-muted whitespace-nowrap">{{ act.createdAt?.slice(0, 19).replace('T', ' ') }}</div>
            <div :class="typeColor(act.activityType)" class="text-[10px] mt-0.5">type {{ act.activityType }}</div>
          </div>
        </div>
      </div>

      <div v-if="nextCursor" class="p-4 border-t border-s1-border">
        <button @click="fetchList(false)" :disabled="loading" class="btn-ghost text-sm w-full">
          Load more
        </button>
      </div>
    </div>
  </div>
</template>
