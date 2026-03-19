<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { RefreshCw, Plus } from 'lucide-vue-next'
import { esCasesApi } from '../../api/elastic'
import type { EsCase } from '../../types/elastic'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const router = useRouter()
const loading = ref(false)
const cases = ref<EsCase[]>([])
const total = ref(0)
const page = ref(1)
const perPage = 25

const showCreateDialog = ref(false)
const newCase = ref({
  title: '',
  description: '',
  severity: 'medium',
  tags: '',
})

function severityBadgeClass(severity: string): string {
  switch (severity) {
    case 'critical': return 'bg-red-500/15 text-red-400'
    case 'high': return 'bg-orange-500/15 text-orange-400'
    case 'medium': return 'bg-yellow-500/15 text-yellow-400'
    case 'low': return 'bg-blue-500/15 text-blue-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function statusBadgeClass(status: string): string {
  switch (status) {
    case 'open': return 'bg-blue-500/15 text-blue-400'
    case 'in-progress': return 'bg-yellow-500/15 text-yellow-400'
    case 'closed': return 'bg-green-500/15 text-green-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function fetchCases(p = 1): Promise<void> {
  loading.value = true
  page.value = p
  try {
    const res = await esCasesApi.find({ page: p, per_page: perPage, sortField: 'created_at', sortOrder: 'desc' })
    cases.value = res.data ?? []
    total.value = res.total ?? cases.value.length
  } finally {
    loading.value = false
  }
}

const hasPrev = computed(() => page.value > 1)
const hasNext = computed(() => page.value * perPage < total.value)

async function createCase(): Promise<void> {
  loading.value = true
  try {
    await esCasesApi.create({
      title: newCase.value.title,
      description: newCase.value.description,
      severity: newCase.value.severity,
      tags: newCase.value.tags ? newCase.value.tags.split(',').map(t => t.trim()) : [],
      connector: { id: 'none', name: 'none', type: '.none', fields: null },
      settings: { syncAlerts: true },
    })
    showCreateDialog.value = false
    newCase.value = { title: '', description: '', severity: 'medium', tags: '' }
    await fetchCases()
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
          <span class="text-purple-500 font-bold">ES</span> Cases
        </h1>
        <p class="text-s1-muted text-sm">{{ total }} cases total</p>
      </div>
      <div class="flex items-center gap-2">
        <button @click="showCreateDialog = true" class="btn-ghost flex items-center gap-2 text-purple-400">
          <Plus class="w-3.5 h-3.5" /> Create Case
        </button>
        <button @click="fetchCases(page)" class="btn-ghost flex items-center gap-2">
          <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
          Refresh
        </button>
      </div>
    </div>

    <!-- Create dialog -->
    <div v-if="showCreateDialog" class="card p-5 border-purple-500/40 space-y-4">
      <h3 class="text-sm font-semibold text-s1-text">Create Case</h3>
      <div class="grid grid-cols-2 gap-4">
        <div>
          <label class="text-xs text-s1-muted">Title</label>
          <input v-model="newCase.title" class="input mt-1" placeholder="Case title" />
        </div>
        <div>
          <label class="text-xs text-s1-muted">Severity</label>
          <select v-model="newCase.severity" class="select mt-1">
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <div class="col-span-2">
          <label class="text-xs text-s1-muted">Description</label>
          <input v-model="newCase.description" class="input mt-1" placeholder="Case description" />
        </div>
        <div class="col-span-2">
          <label class="text-xs text-s1-muted">Tags (comma-separated)</label>
          <input v-model="newCase.tags" class="input mt-1" placeholder="tag1, tag2" />
        </div>
      </div>
      <div class="flex items-center gap-2">
        <button @click="createCase()" :disabled="!newCase.title || loading"
          class="btn-ghost text-purple-400 text-sm">
          Create
        </button>
        <button @click="showCreateDialog = false" class="btn-ghost text-sm">Cancel</button>
      </div>
    </div>

    <!-- Table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Title</th>
            <th class="table-header text-left">Status</th>
            <th class="table-header text-left">Severity</th>
            <th class="table-header text-left">Tags</th>
            <th class="table-header text-left">Comments</th>
            <th class="table-header text-left">Created</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !cases.length" :rows="8" />
          <template v-else>
            <tr
              v-for="c in cases" :key="c.id"
              class="table-row"
              @click="router.push(`/elastic/cases/${c.id}`)"
            >
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm truncate max-w-[250px]">{{ c.title }}</div>
                <div class="text-xs text-s1-muted">by {{ c.created_by?.username ?? 'unknown' }}</div>
              </td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="statusBadgeClass(c.status)">
                  {{ c.status }}
                </span>
              </td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="severityBadgeClass(c.severity)">
                  {{ c.severity }}
                </span>
              </td>
              <td class="table-cell">
                <div class="flex flex-wrap gap-1">
                  <span v-for="tag in (c.tags ?? []).slice(0, 3)" :key="tag"
                    class="text-xs px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400">
                    {{ tag }}
                  </span>
                </div>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ c.total_comment }}</td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(c.created_at) }}</td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !cases.length"
        icon="--"
        title="No cases found"
        description="Create a case to start tracking investigations."
      />

      <!-- Pagination -->
      <div v-if="cases.length > 0" class="p-4 flex items-center justify-between border-t border-s1-border">
        <button @click="fetchCases(page - 1)" class="btn-ghost text-sm" :disabled="!hasPrev || loading">
          Previous
        </button>
        <span class="text-xs text-s1-muted">
          Page {{ page }} of {{ Math.ceil(total / perPage) }}
        </span>
        <button @click="fetchCases(page + 1)" class="btn-ghost text-sm" :disabled="!hasNext || loading">
          Next
        </button>
      </div>
    </div>
  </div>
</template>
