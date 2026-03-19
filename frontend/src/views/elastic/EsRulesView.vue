<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { RefreshCw, Plus, Trash2 } from 'lucide-vue-next'
import { esRulesApi } from '../../api/elastic'
import type { EsRule } from '../../types/elastic'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const rules = ref<EsRule[]>([])
const total = ref(0)
const page = ref(1)
const perPage = 25

// Filters
const filterSeverity = ref('')
const filterEnabled = ref('')

const showCreateDialog = ref(false)
const newRule = ref({
  name: '',
  description: '',
  severity: 'medium',
  risk_score: 50,
  type: 'query',
  enabled: true,
})

// Selection for bulk
const selected = ref<Set<string>>(new Set())

function severityBadgeClass(severity: string): string {
  switch (severity) {
    case 'critical': return 'bg-red-500/15 text-red-400'
    case 'high': return 'bg-orange-500/15 text-orange-400'
    case 'medium': return 'bg-yellow-500/15 text-yellow-400'
    case 'low': return 'bg-blue-500/15 text-blue-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function fetchRules(p = 1): Promise<void> {
  loading.value = true
  page.value = p
  try {
    const params: Record<string, unknown> = { page: p, per_page: perPage }

    const filters: string[] = []
    if (filterSeverity.value) filters.push(`alert.attributes.params.severity: ${filterSeverity.value}`)
    if (filterEnabled.value) filters.push(`alert.attributes.enabled: ${filterEnabled.value}`)
    if (filters.length) params['filter'] = filters.join(' AND ')

    const res = await esRulesApi.find(params)
    rules.value = res.data ?? []
    total.value = res.total ?? rules.value.length
  } finally {
    loading.value = false
  }
}

const hasPrev = computed(() => page.value > 1)
const hasNext = computed(() => page.value * perPage < total.value)

async function createRule(): Promise<void> {
  loading.value = true
  try {
    await esRulesApi.create(newRule.value)
    showCreateDialog.value = false
    newRule.value = { name: '', description: '', severity: 'medium', risk_score: 50, type: 'query', enabled: true }
    await fetchRules()
  } finally {
    loading.value = false
  }
}

async function deleteRule(id: string): Promise<void> {
  loading.value = true
  try {
    await esRulesApi.delete(id)
    await fetchRules(page.value)
  } finally {
    loading.value = false
  }
}

async function toggleEnabled(rule: EsRule): Promise<void> {
  try {
    await esRulesApi.bulkAction({
      action: rule.enabled ? 'disable' : 'enable',
      ids: [rule.id],
    })
    rule.enabled = !rule.enabled
  } catch {
    // Revert on failure will be handled by refetch
    await fetchRules(page.value)
  }
}

async function bulkEnable(enable: boolean): Promise<void> {
  if (selected.value.size === 0) return
  loading.value = true
  try {
    await esRulesApi.bulkAction({
      action: enable ? 'enable' : 'disable',
      ids: [...selected.value],
    })
    selected.value.clear()
    await fetchRules(page.value)
  } finally {
    loading.value = false
  }
}

watch([filterSeverity, filterEnabled], () => fetchRules())

onMounted(() => fetchRules())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="text-purple-500 font-bold">ES</span> Detection Rules
        </h1>
        <p class="text-s1-muted text-sm">{{ total }} rules total</p>
      </div>
      <div class="flex items-center gap-2">
        <button @click="showCreateDialog = true" class="btn-ghost flex items-center gap-2 text-purple-400">
          <Plus class="w-3.5 h-3.5" /> Create Rule
        </button>
        <button @click="fetchRules(page)" class="btn-ghost flex items-center gap-2">
          <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
          Refresh
        </button>
      </div>
    </div>

    <!-- Filter bar -->
    <div class="card p-4 flex flex-wrap gap-3">
      <select v-model="filterSeverity" class="select">
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <select v-model="filterEnabled" class="select">
        <option value="">All Status</option>
        <option value="true">Enabled</option>
        <option value="false">Disabled</option>
      </select>
    </div>

    <!-- Bulk action bar -->
    <Transition name="slide-down">
      <div v-if="selected.size > 0" class="card px-4 py-3 flex items-center gap-3 border-purple-500/40">
        <span class="text-sm text-s1-text font-medium">{{ selected.size }} selected</span>
        <div class="h-4 w-px bg-s1-border"></div>
        <button @click="bulkEnable(true)" class="btn-ghost text-xs text-green-400">Enable All</button>
        <button @click="bulkEnable(false)" class="btn-ghost text-xs text-red-400">Disable All</button>
      </div>
    </Transition>

    <!-- Create dialog -->
    <div v-if="showCreateDialog" class="card p-5 border-purple-500/40 space-y-4">
      <h3 class="text-sm font-semibold text-s1-text">Create Detection Rule</h3>
      <div class="grid grid-cols-2 gap-4">
        <div>
          <label class="text-xs text-s1-muted">Name</label>
          <input v-model="newRule.name" class="input mt-1" placeholder="Rule name" />
        </div>
        <div>
          <label class="text-xs text-s1-muted">Description</label>
          <input v-model="newRule.description" class="input mt-1" placeholder="Rule description" />
        </div>
        <div>
          <label class="text-xs text-s1-muted">Severity</label>
          <select v-model="newRule.severity" class="select mt-1">
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <div>
          <label class="text-xs text-s1-muted">Risk Score (0-100)</label>
          <input v-model.number="newRule.risk_score" type="number" min="0" max="100" class="input mt-1" />
        </div>
        <div>
          <label class="text-xs text-s1-muted">Type</label>
          <select v-model="newRule.type" class="select mt-1">
            <option value="query">Query</option>
            <option value="eql">EQL</option>
            <option value="threshold">Threshold</option>
            <option value="machine_learning">Machine Learning</option>
          </select>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <button @click="createRule()" :disabled="!newRule.name || loading"
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
            <th class="table-header w-10">
              <input type="checkbox"
                :checked="rules.length > 0 && rules.every(r => selected.has(r.id))"
                @change="rules.every(r => selected.has(r.id)) ? selected.clear() : rules.forEach(r => selected.add(r.id))"
                class="rounded border-s1-border bg-s1-bg accent-purple-500" />
            </th>
            <th class="table-header text-left">Name</th>
            <th class="table-header text-left">Severity</th>
            <th class="table-header text-left">Risk Score</th>
            <th class="table-header text-left">Enabled</th>
            <th class="table-header text-left">Type</th>
            <th class="table-header text-left">Tags</th>
            <th class="table-header w-10"></th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !rules.length" :rows="8" />
          <template v-else>
            <tr v-for="rule in rules" :key="rule.id" class="table-row"
              :class="selected.has(rule.id) ? 'bg-purple-500/5' : ''">
              <td class="table-cell" @click.stop>
                <input type="checkbox" :checked="selected.has(rule.id)"
                  @change="selected.has(rule.id) ? selected.delete(rule.id) : selected.add(rule.id)"
                  class="rounded border-s1-border bg-s1-bg accent-purple-500" />
              </td>
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm truncate max-w-[200px]">{{ rule.name }}</div>
              </td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="severityBadgeClass(rule.severity)">
                  {{ rule.severity }}
                </span>
              </td>
              <td class="table-cell text-sm text-s1-text">{{ rule.risk_score }}</td>
              <td class="table-cell" @click.stop>
                <button
                  @click="toggleEnabled(rule)"
                  class="relative inline-flex h-5 w-9 items-center rounded-full transition-colors"
                  :class="rule.enabled ? 'bg-purple-500' : 'bg-gray-600'"
                >
                  <span
                    class="inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform"
                    :class="rule.enabled ? 'translate-x-[18px]' : 'translate-x-[3px]'"
                  ></span>
                </button>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ rule.type }}</td>
              <td class="table-cell">
                <div class="flex flex-wrap gap-1">
                  <span v-for="tag in (rule.tags ?? []).slice(0, 3)" :key="tag"
                    class="text-xs px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400">
                    {{ tag }}
                  </span>
                </div>
              </td>
              <td class="table-cell" @click.stop>
                <button @click="deleteRule(rule.id)" class="btn-ghost text-red-400 p-1">
                  <Trash2 class="w-3.5 h-3.5" />
                </button>
              </td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !rules.length"
        icon="--"
        title="No rules found"
        description="No detection rules match your current filters."
      />

      <!-- Pagination -->
      <div v-if="rules.length > 0" class="p-4 flex items-center justify-between border-t border-s1-border">
        <button @click="fetchRules(page - 1)" class="btn-ghost text-sm" :disabled="!hasPrev || loading">
          Previous
        </button>
        <span class="text-xs text-s1-muted">
          Page {{ page }} of {{ Math.ceil(total / perPage) }}
        </span>
        <button @click="fetchRules(page + 1)" class="btn-ghost text-sm" :disabled="!hasNext || loading">
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
