<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { Plus, Trash2 } from 'lucide-vue-next'
import { blocklistApi } from '../api/misc'
import LoadingSkeleton from '../components/shared/LoadingSkeleton.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import type { BlocklistEntry } from '../types'

const items = ref<BlocklistEntry[]>([])
const total = ref(0)
const loading = ref(true)
const query = ref('')
const showAdd = ref(false)
const adding = ref(false)

const error = ref('')
const form = ref({ value: '', type: 'black_hash', osType: 'windows', description: '' })

async function fetchList(): Promise<void> {
  loading.value = true
  try {
    const params: Record<string, unknown> = { limit: 200 }
    if (query.value) params['query'] = query.value
    const res = await blocklistApi.list(params)
    items.value = res.data
    total.value = res.pagination?.totalItems ?? res.data.length
  } finally {
    loading.value = false
  }
}

let debounceTimer: ReturnType<typeof setTimeout>
function onQuery(): void {
  clearTimeout(debounceTimer)
  debounceTimer = setTimeout(fetchList, 300)
}

async function addEntry(): Promise<void> {
  if (!form.value.value.trim()) return
  adding.value = true
  try {
    await blocklistApi.create({
      value: form.value.value.trim(),
      type: form.value.type,
      osType: form.value.osType,
      description: form.value.description,
    })
    form.value = { value: '', type: 'black_hash', osType: 'windows', description: '' }
    showAdd.value = false
    await fetchList()
  } finally {
    adding.value = false
  }
}

async function deleteEntry(id: string): Promise<void> {
  error.value = ''
  try {
    await blocklistApi.delete(id)
    items.value = items.value.filter(e => e.id !== id)
    total.value -= 1
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : 'Failed to delete entry'
  }
}

onMounted(fetchList)
onUnmounted(() => clearTimeout(debounceTimer))
</script>

<template>
  <div class="space-y-4">
    <div v-if="error" class="error-banner">{{ error }}</div>
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-s1-text">Blocklist</h1>
        <p class="text-s1-muted text-sm">{{ total }} blocked hashes</p>
      </div>
      <button @click="showAdd = !showAdd" class="btn-primary flex items-center gap-2 text-sm">
        <Plus class="w-4 h-4" /> Add Hash
      </button>
    </div>

    <!-- Add form -->
    <div v-if="showAdd" class="card p-4 space-y-3">
      <div class="text-sm font-semibold text-s1-text">Add Blocklist Entry</div>
      <div class="grid grid-cols-2 gap-3">
        <div class="col-span-2">
          <label class="text-xs text-s1-muted mb-1 block">Hash Value</label>
          <input v-model="form.value" placeholder="SHA-256 or SHA-1 hash" class="input w-full text-sm font-mono" />
        </div>
        <div>
          <label class="text-xs text-s1-muted mb-1 block">Type</label>
          <select v-model="form.type" class="input w-full text-sm">
            <option value="black_hash">black_hash</option>
          </select>
        </div>
        <div>
          <label class="text-xs text-s1-muted mb-1 block">OS</label>
          <select v-model="form.osType" class="input w-full text-sm">
            <option value="windows">Windows</option>
            <option value="macos">macOS</option>
            <option value="linux">Linux</option>
          </select>
        </div>
        <div class="col-span-2">
          <label class="text-xs text-s1-muted mb-1 block">Description (optional)</label>
          <input v-model="form.description" placeholder="Why is this hash blocked?" class="input w-full text-sm" />
        </div>
      </div>
      <div class="flex gap-2 justify-end">
        <button @click="showAdd = false" class="btn-ghost text-sm">Cancel</button>
        <button @click="addEntry" :disabled="adding || !form.value.trim()" class="btn-primary text-sm">
          {{ adding ? 'Adding…' : 'Add' }}
        </button>
      </div>
    </div>

    <!-- Search -->
    <div class="card p-3">
      <input v-model="query" @input="onQuery" class="input w-full" placeholder="Search by hash or description..." />
    </div>

    <div class="card overflow-hidden">
      <div v-if="loading"><LoadingSkeleton :rows="6" /></div>
      <EmptyState v-else-if="!items.length" title="Blocklist empty" description="No hashes are currently blocked" />
      <table v-else class="w-full text-sm">
        <thead class="border-b border-s1-border">
          <tr class="text-left text-xs text-s1-muted uppercase tracking-wide">
            <th class="px-5 py-3">Hash</th>
            <th class="px-5 py-3">Type</th>
            <th class="px-5 py-3">Description</th>
            <th class="px-5 py-3">OS</th>
            <th class="px-5 py-3">Created</th>
            <th class="px-5 py-3"></th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="entry in items" :key="entry.id"
            class="border-b border-s1-border/50 hover:bg-s1-hover transition-colors"
          >
            <td class="px-5 py-3 font-mono text-xs text-s1-text">{{ entry.value }}</td>
            <td class="px-5 py-3 text-s1-muted uppercase text-xs">{{ entry.type }}</td>
            <td class="px-5 py-3 text-s1-muted text-xs">{{ entry.description || '—' }}</td>
            <td class="px-5 py-3 text-s1-muted capitalize">{{ entry.osType || 'all' }}</td>
            <td class="px-5 py-3 text-s1-muted text-xs">{{ entry.createdAt?.slice(0, 10) }}</td>
            <td class="px-5 py-3">
              <button @click="deleteEntry(entry.id)" class="text-s1-muted hover:text-s1-danger transition-colors">
                <Trash2 class="w-4 h-4" />
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
