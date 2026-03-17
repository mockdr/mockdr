<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { exclusionsApi } from '../api/misc'
import LoadingSkeleton from '../components/shared/LoadingSkeleton.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import { Plus, Trash2 } from 'lucide-vue-next'
import type { Exclusion } from '../types'

const items = ref<Exclusion[]>([])
const total = ref(0)
const loading = ref(true)
const showAdd = ref(false)
const newPath = ref('')
const newType = ref('path')
const newOs = ref('windows')
const error = ref('')

const EXCLUSION_TYPES = ['path', 'file_type', 'certificate', 'hash', 'browser']
const OS_TYPES = ['windows', 'macos', 'linux', 'all']

async function fetchList(): Promise<void> {
  loading.value = true
  try {
    const res = await exclusionsApi.list({ limit: 200 })
    items.value = res.data
    total.value = res.pagination?.totalItems ?? res.data.length
  } finally {
    loading.value = false
  }
}

async function addExclusion(): Promise<void> {
  if (!newPath.value.trim()) return
  error.value = ''
  try {
    await exclusionsApi.create({
      value: newPath.value,
      type: newType.value,
      osType: newOs.value,
      mode: 'suppress',
    })
    newPath.value = ''
    showAdd.value = false
    await fetchList()
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : 'Failed to add exclusion'
  }
}

async function removeExclusion(id: string): Promise<void> {
  if (!confirm('Are you sure you want to delete this exclusion?')) return
  error.value = ''
  try {
    await exclusionsApi.delete(id)
    items.value = items.value.filter(e => e.id !== id)
    total.value--
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : 'Failed to remove exclusion'
  }
}

onMounted(fetchList)
</script>

<template>
  <div class="space-y-4">
    <div v-if="error" class="error-banner">{{ error }}</div>
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-s1-text">Exclusions</h1>
        <p class="text-s1-muted text-sm">{{ total }} exclusions</p>
      </div>
      <button @click="showAdd = !showAdd" class="btn-primary flex items-center gap-2 text-sm">
        <Plus class="w-4 h-4" /> Add Exclusion
      </button>
    </div>

    <!-- Add form -->
    <div v-if="showAdd" class="card p-4 space-y-3">
      <div class="grid grid-cols-3 gap-3">
        <div class="col-span-3">
          <label class="text-xs text-s1-muted mb-1 block">Value (path, hash, etc.)</label>
          <input v-model="newPath" class="input w-full" placeholder="e.g. C:\Windows\System32\*.exe" />
        </div>
        <div>
          <label class="text-xs text-s1-muted mb-1 block">Type</label>
          <select v-model="newType" class="input w-full text-sm">
            <option v-for="t in EXCLUSION_TYPES" :key="t" :value="t">{{ t.replace('_', ' ') }}</option>
          </select>
        </div>
        <div>
          <label class="text-xs text-s1-muted mb-1 block">OS</label>
          <select v-model="newOs" class="input w-full text-sm">
            <option v-for="os in OS_TYPES" :key="os" :value="os">{{ os }}</option>
          </select>
        </div>
        <div class="flex items-end gap-2">
          <button @click="addExclusion" class="btn-primary text-sm w-full">Add</button>
          <button @click="showAdd = false" class="btn-ghost text-sm w-full">Cancel</button>
        </div>
      </div>
    </div>

    <div class="card overflow-hidden">
      <div v-if="loading"><LoadingSkeleton :rows="6" /></div>
      <EmptyState v-else-if="!items.length" title="No exclusions" description="No exclusions configured" />
      <table v-else class="w-full text-sm">
        <thead class="border-b border-s1-border">
          <tr class="text-left text-xs text-s1-muted uppercase tracking-wide">
            <th class="px-5 py-3">Value</th>
            <th class="px-5 py-3">Type</th>
            <th class="px-5 py-3">OS</th>
            <th class="px-5 py-3">Mode</th>
            <th class="px-5 py-3">Created</th>
            <th class="px-5 py-3"></th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="ex in items" :key="ex.id"
            class="border-b border-s1-border/50 hover:bg-s1-hover transition-colors"
          >
            <td class="px-5 py-3 font-mono text-xs text-s1-text max-w-sm truncate">{{ ex.value }}</td>
            <td class="px-5 py-3 text-s1-muted capitalize">{{ ex.type?.replace('_', ' ') }}</td>
            <td class="px-5 py-3 text-s1-muted capitalize">{{ ex.osType }}</td>
            <td class="px-5 py-3 text-s1-muted capitalize">{{ ex.mode }}</td>
            <td class="px-5 py-3 text-s1-muted text-xs">{{ ex.createdAt?.slice(0, 10) }}</td>
            <td class="px-5 py-3">
              <button @click="removeExclusion(ex.id)" class="text-s1-muted hover:text-s1-danger transition-colors">
                <Trash2 class="w-4 h-4" />
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
