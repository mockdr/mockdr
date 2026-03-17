<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { Plus, Trash2 } from 'lucide-vue-next'
import { iocsApi } from '../api/misc'
import LoadingSkeleton from '../components/shared/LoadingSkeleton.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import type { Ioc } from '../types'

const items = ref<Ioc[]>([])
const total = ref(0)
const loading = ref(true)
const showAdd = ref(false)
const adding = ref(false)
const selected = ref<Set<string>>(new Set())
const deleting = ref(false)

const form = ref({ type: 'IPV4', value: '', name: '', description: '' })

const IOC_TYPES = ['IPV4', 'IPV6', 'DNS', 'URL', 'SHA1', 'SHA256', 'MD5']

async function fetchList(): Promise<void> {
  loading.value = true
  try {
    const res = await iocsApi.list({ limit: 200 })
    items.value = res.data as Ioc[]
    total.value = res.pagination?.totalItems ?? res.data.length
  } finally {
    loading.value = false
  }
}

async function addIoc(): Promise<void> {
  if (!form.value.value.trim()) return
  adding.value = true
  try {
    await iocsApi.create({
      type: form.value.type,
      value: form.value.value.trim(),
      name: form.value.name || form.value.value.trim(),
      description: form.value.description,
    })
    form.value = { type: 'IPV4', value: '', name: '', description: '' }
    showAdd.value = false
    await fetchList()
  } finally {
    adding.value = false
  }
}

function toggleSelect(id: string): void {
  if (selected.value.has(id)) selected.value.delete(id)
  else selected.value.add(id)
  selected.value = new Set(selected.value)
}

function toggleAll(): void {
  if (selected.value.size === items.value.length) selected.value = new Set()
  else selected.value = new Set(items.value.map(i => i.uuid))
}

async function deleteSelected(): Promise<void> {
  if (!selected.value.size) return
  if (!confirm('Are you sure you want to delete the selected IOCs?')) return
  deleting.value = true
  try {
    await iocsApi.delete([...selected.value])
    items.value = items.value.filter(i => !selected.value.has(i.uuid))
    total.value = items.value.length
    selected.value = new Set()
  } finally {
    deleting.value = false
  }
}

onMounted(fetchList)
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-s1-text">Threat Intelligence — IOCs</h1>
        <p class="text-s1-muted text-sm">{{ total }} indicators of compromise</p>
      </div>
      <div class="flex gap-2">
        <button
          v-if="selected.size"
          @click="deleteSelected"
          :disabled="deleting"
          class="btn-ghost flex items-center gap-2 text-sm text-s1-danger border-s1-danger/30 hover:bg-s1-danger/10"
        >
          <Trash2 class="w-4 h-4" /> Delete ({{ selected.size }})
        </button>
        <button @click="showAdd = !showAdd" class="btn-primary flex items-center gap-2 text-sm">
          <Plus class="w-4 h-4" /> Add IOC
        </button>
      </div>
    </div>

    <!-- Add form -->
    <div v-if="showAdd" class="card p-4 space-y-3">
      <div class="text-sm font-semibold text-s1-text">Add Indicator of Compromise</div>
      <div class="grid grid-cols-2 gap-3">
        <div>
          <label class="text-xs text-s1-muted mb-1 block">Type</label>
          <select v-model="form.type" class="input w-full text-sm">
            <option v-for="t in IOC_TYPES" :key="t" :value="t">{{ t }}</option>
          </select>
        </div>
        <div>
          <label class="text-xs text-s1-muted mb-1 block">Value</label>
          <input v-model="form.value" placeholder="IP, domain, hash, URL…" class="input w-full text-sm font-mono" />
        </div>
        <div>
          <label class="text-xs text-s1-muted mb-1 block">Name (optional)</label>
          <input v-model="form.name" placeholder="Indicator name" class="input w-full text-sm" />
        </div>
        <div>
          <label class="text-xs text-s1-muted mb-1 block">Description (optional)</label>
          <input v-model="form.description" placeholder="Context or campaign" class="input w-full text-sm" />
        </div>
      </div>
      <div class="flex gap-2 justify-end">
        <button @click="showAdd = false" class="btn-ghost text-sm">Cancel</button>
        <button @click="addIoc" :disabled="adding || !form.value.trim()" class="btn-primary text-sm">
          {{ adding ? 'Adding…' : 'Add IOC' }}
        </button>
      </div>
    </div>

    <div class="card overflow-hidden">
      <div v-if="loading"><LoadingSkeleton :rows="6" /></div>
      <EmptyState v-else-if="!items.length" title="No IOCs" description="No indicators of compromise configured" />
      <table v-else class="w-full text-sm">
        <thead class="border-b border-s1-border">
          <tr class="text-left text-xs text-s1-muted uppercase tracking-wide">
            <th class="px-4 py-3">
              <input
                type="checkbox"
                :checked="selected.size === items.length && items.length > 0"
                @change="toggleAll"
                class="rounded"
              />
            </th>
            <th class="px-5 py-3">Type</th>
            <th class="px-5 py-3">Value</th>
            <th class="px-5 py-3">Name</th>
            <th class="px-5 py-3">Description</th>
            <th class="px-5 py-3">Created</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="ioc in items" :key="ioc.uuid"
            class="border-b border-s1-border/50 hover:bg-s1-hover transition-colors"
            :class="selected.has(ioc.uuid) ? 'bg-s1-primary/5' : ''"
          >
            <td class="px-4 py-3">
              <input type="checkbox" :checked="selected.has(ioc.uuid)" @change="toggleSelect(ioc.uuid)" class="rounded" />
            </td>
            <td class="px-5 py-3">
              <span class="text-xs font-mono px-2 py-0.5 rounded bg-s1-border text-s1-text uppercase">{{ ioc.type }}</span>
            </td>
            <td class="px-5 py-3 font-mono text-xs text-s1-text max-w-[200px] truncate">{{ ioc.value }}</td>
            <td class="px-5 py-3 text-s1-text text-xs">{{ ioc.name || '—' }}</td>
            <td class="px-5 py-3 text-s1-muted text-xs">{{ ioc.description || '—' }}</td>
            <td class="px-5 py-3 text-s1-muted text-xs">{{ ioc.creationTime?.slice(0, 10) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
