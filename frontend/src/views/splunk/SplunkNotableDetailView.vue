<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { ShieldAlert, ArrowLeft } from 'lucide-vue-next'
import { splunkNotableApi } from '../../api/splunk'
import type { SplunkNotable } from '../../types/splunk'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

const route = useRoute()
const loading = ref(true)
const notable = ref<SplunkNotable | null>(null)
const comment = ref('')

const eventId = route.params.id as string

function severityBadgeClass(severity: string): string {
  switch ((severity ?? '').toLowerCase()) {
    case 'critical': return 'bg-red-500/15 text-red-400'
    case 'high': return 'bg-orange-500/15 text-orange-400'
    case 'medium': return 'bg-yellow-500/15 text-yellow-400'
    case 'low': return 'bg-blue-500/15 text-blue-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function statusLabel(status: string): string {
  return { '1': 'New', '2': 'In Progress', '3': 'Pending', '4': 'Resolved', '5': 'Closed' }[status] ?? status
}

function formatTime(ts: string): string {
  if (!ts) return ''
  return new Date(parseFloat(ts) * 1000).toLocaleString()
}

async function fetchNotable(): Promise<void> {
  loading.value = true
  try {
    const all = await splunkNotableApi.list()
    notable.value = all.find(n => n.event_id === eventId) ?? null
  } finally {
    loading.value = false
  }
}

async function updateNotable(field: string, value: string): Promise<void> {
  await splunkNotableApi.update(eventId, { [field]: value })
  await fetchNotable()
}

async function addComment(): Promise<void> {
  if (!comment.value.trim()) return
  await splunkNotableApi.update(eventId, { comment: comment.value })
  comment.value = ''
  await fetchNotable()
}

onMounted(fetchNotable)
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center gap-3">
      <RouterLink to="/splunk/notables" class="p-1.5 rounded hover:bg-s1-hover">
        <ArrowLeft class="w-4 h-4 text-s1-muted" />
      </RouterLink>
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <ShieldAlert class="w-5 h-5 text-red-400" />
          Notable Event Detail
        </h1>
      </div>
    </div>

    <LoadingSkeleton v-if="loading" :rows="10" />

    <template v-else-if="notable">
      <!-- Key fields -->
      <div class="card p-5 space-y-4">
        <div class="grid grid-cols-2 gap-4">
          <div>
            <div class="text-xs text-s1-muted uppercase">Rule Name</div>
            <div class="text-s1-text font-medium mt-1">{{ notable.rule_name }}</div>
          </div>
          <div>
            <div class="text-xs text-s1-muted uppercase">Event ID</div>
            <div class="text-s1-text font-mono text-xs mt-1">{{ notable.event_id }}</div>
          </div>
          <div>
            <div class="text-xs text-s1-muted uppercase">Severity</div>
            <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium mt-1" :class="severityBadgeClass(notable.severity)">
              {{ notable.severity }}
            </span>
          </div>
          <div>
            <div class="text-xs text-s1-muted uppercase">Status</div>
            <select
              :value="notable.status"
              @change="updateNotable('status', ($event.target as HTMLSelectElement).value)"
              class="bg-s1-input border border-s1-border rounded px-2 py-1 text-sm text-s1-text mt-1"
            >
              <option value="1">New</option>
              <option value="2">In Progress</option>
              <option value="3">Pending</option>
              <option value="4">Resolved</option>
              <option value="5">Closed</option>
            </select>
          </div>
          <div>
            <div class="text-xs text-s1-muted uppercase">Destination</div>
            <div class="text-s1-text mt-1">{{ notable.dest || '—' }}</div>
          </div>
          <div>
            <div class="text-xs text-s1-muted uppercase">Owner</div>
            <div class="text-s1-text mt-1">{{ notable.owner }}</div>
          </div>
          <div>
            <div class="text-xs text-s1-muted uppercase">User</div>
            <div class="text-s1-text mt-1">{{ notable.user || '—' }}</div>
          </div>
          <div>
            <div class="text-xs text-s1-muted uppercase">Time</div>
            <div class="text-s1-text mt-1">{{ formatTime(notable.time) }}</div>
          </div>
        </div>
        <div>
          <div class="text-xs text-s1-muted uppercase">Description</div>
          <div class="text-s1-text mt-1">{{ notable.description }}</div>
        </div>
        <div>
          <div class="text-xs text-s1-muted uppercase">Drilldown Search</div>
          <div class="text-s1-text font-mono text-xs mt-1 bg-s1-hover p-2 rounded">{{ notable.drilldown_search }}</div>
        </div>
      </div>

      <!-- Comment -->
      <div class="card p-5">
        <h3 class="text-sm font-semibold text-s1-text mb-3">Add Comment</h3>
        <div class="flex gap-3">
          <input
            v-model="comment"
            type="text"
            class="flex-1 bg-s1-input border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text"
            placeholder="Add a comment..."
            @keyup.enter="addComment"
          />
          <button
            @click="addComment"
            class="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm"
          >
            Add
          </button>
        </div>
      </div>
    </template>

    <div v-else class="card p-12 text-center text-s1-muted">Notable event not found</div>
  </div>
</template>
