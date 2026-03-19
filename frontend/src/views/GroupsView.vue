<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { Trash2, Pencil, Plus, X } from 'lucide-vue-next'
import { groupsApi, sitesApi } from '../api/misc'
import LoadingSkeleton from '../components/shared/LoadingSkeleton.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import type { Group, Site } from '../types'

const items = ref<Group[]>([])
const total = ref(0)
const loading = ref(true)
const siteFilter = ref<string>('')   // holds siteId
const sites = ref<Site[]>([])
const deletingId = ref<string | null>(null)
const confirmDeleteId = ref<string | null>(null)

async function fetchList(): Promise<void> {
  loading.value = true
  try {
    const [groupsRes, sitesRes] = await Promise.all([
      groupsApi.list({ limit: 200 }),
      sitesApi.list({ limit: 100 }),
    ])
    items.value = groupsRes.data
    total.value = groupsRes.pagination?.totalItems ?? groupsRes.data.length
    sites.value = sitesRes.data.sites
  } finally {
    loading.value = false
  }
}

onMounted(fetchList)

const filtered = computed(() =>
  siteFilter.value ? items.value.filter(g => g.siteId === siteFilter.value) : items.value
)

// ── Modal state ───────────────────────────────────────────────────────────────

type ModalMode = 'create' | 'edit' | null

const modalMode = ref<ModalMode>(null)
const modalSaving = ref(false)
const modalError = ref('')
const editingId = ref<string | null>(null)

const form = reactive({
  name: '',
  siteId: '',
  type: 'static',
  description: '',
  inherits: true,
})

function openCreate(): void {
  modalMode.value = 'create'
  editingId.value = null
  modalError.value = ''
  form.name = ''
  form.siteId = sites.value[0]?.id ?? ''
  form.type = 'static'
  form.description = ''
  form.inherits = true
}

function openEdit(group: Group): void {
  modalMode.value = 'edit'
  editingId.value = group.id
  modalError.value = ''
  form.name = group.name
  form.siteId = group.siteId
  form.type = group.type
  form.description = group.description ?? ''
  form.inherits = group.inherits ?? true
}

function closeModal(): void {
  modalMode.value = null
  editingId.value = null
  modalError.value = ''
}

async function saveModal(): Promise<void> {
  modalSaving.value = true
  if (!form.name.trim()) { modalError.value = 'Name is required'; modalSaving.value = false; return }
  if (modalMode.value === 'create' && !form.siteId) { modalError.value = 'Site is required'; modalSaving.value = false; return }
  modalError.value = ''
  try {
    if (modalMode.value === 'create') {
      await groupsApi.create({
        name: form.name.trim(),
        siteId: form.siteId,
        type: form.type,
        description: form.description || undefined,
        inherits: form.inherits,
      })
    } else if (modalMode.value === 'edit' && editingId.value) {
      await groupsApi.update(editingId.value, {
        name: form.name.trim(),
        type: form.type,
        description: form.description || undefined,
        inherits: form.inherits,
      })
    }
    closeModal()
    await fetchList()
  } catch {
    modalError.value = 'Save failed.'
  } finally {
    modalSaving.value = false
  }
}

// ── Delete ────────────────────────────────────────────────────────────────────

function requestDelete(group: Group): void {
  confirmDeleteId.value = group.id
}

async function confirmDelete(group: Group): Promise<void> {
  deletingId.value = group.id
  confirmDeleteId.value = null
  try {
    await groupsApi.delete(group.id)
    items.value = items.value.filter(g => g.id !== group.id)
    total.value -= 1
  } finally {
    deletingId.value = null
  }
}
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-s1-text">Groups</h1>
        <p class="text-s1-muted text-sm">{{ total }} groups</p>
      </div>
      <div class="flex items-center gap-2">
        <select v-model="siteFilter" class="input w-48 text-sm">
          <option value="">All Sites</option>
          <option v-for="s in sites" :key="s.id" :value="s.id">{{ s.name }}</option>
        </select>
        <button @click="openCreate" class="btn-primary flex items-center gap-1.5 text-sm px-3 py-1.5">
          <Plus class="w-4 h-4" /> New Group
        </button>
      </div>
    </div>

    <div class="card overflow-hidden">
      <div v-if="loading"><LoadingSkeleton :rows="6" /></div>
      <EmptyState v-else-if="!filtered.length" title="No groups" description="No groups found" />
      <table v-else class="w-full text-sm">
        <thead class="border-b border-s1-border">
          <tr class="text-left text-xs text-s1-muted uppercase tracking-wide">
            <th class="px-5 py-3">Name</th>
            <th class="px-5 py-3">Site</th>
            <th class="px-5 py-3">Type</th>
            <th class="px-5 py-3">Agents</th>
            <th class="px-5 py-3">Created</th>
            <th class="px-5 py-3"></th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="group in filtered" :key="group.id"
            class="border-b border-s1-border/50 hover:bg-s1-hover transition-colors"
          >
            <td class="px-5 py-3">
              <div class="text-s1-text font-medium">{{ group.name }}</div>
              <div class="text-xs text-s1-muted font-mono">{{ group.id }}</div>
            </td>
            <td class="px-5 py-3 text-s1-muted">{{ sites.find(s => s.id === group.siteId)?.name ?? group.siteId }}</td>
            <td class="px-5 py-3 text-s1-muted capitalize">{{ group.type }}</td>
            <td class="px-5 py-3 text-s1-text">{{ group.totalAgents ?? 0 }}</td>
            <td class="px-5 py-3 text-s1-muted text-xs">{{ group.createdAt?.slice(0, 10) }}</td>
            <td class="px-5 py-3">
              <div class="flex items-center gap-2">
                <button
                  @click="openEdit(group)"
                  class="text-s1-muted hover:text-s1-primary transition-colors"
                  title="Edit group"
                >
                  <Pencil class="w-3.5 h-3.5" />
                </button>
                <template v-if="!group.isDefault">
                  <button
                    v-if="confirmDeleteId !== group.id"
                    @click="requestDelete(group)"
                    :disabled="deletingId === group.id"
                    class="text-s1-muted hover:text-s1-danger transition-colors disabled:opacity-40"
                    title="Delete group"
                  >
                    <Trash2 class="w-3.5 h-3.5" />
                  </button>
                  <template v-else>
                    <button @click="confirmDelete(group)" class="text-xs text-s1-danger hover:opacity-80">
                      Confirm
                    </button>
                    <button @click="confirmDeleteId = null" class="text-xs text-s1-muted hover:opacity-80">
                      <X class="w-3.5 h-3.5" />
                    </button>
                  </template>
                </template>
                <span v-if="group.isDefault" class="text-xs text-s1-muted italic">default</span>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Create / Edit Modal -->
    <div
      v-if="modalMode"
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
      @click.self="closeModal"
    >
      <div class="card w-full max-w-md p-6 space-y-4">
        <div class="flex items-center justify-between">
          <h2 class="text-lg font-bold text-s1-text">{{ modalMode === 'create' ? 'New Group' : 'Edit Group' }}</h2>
          <button @click="closeModal" class="text-s1-muted hover:text-s1-text"><X class="w-5 h-5" /></button>
        </div>

        <div class="space-y-3">
          <div>
            <label class="block text-xs text-s1-muted mb-1">Name <span class="text-s1-danger">*</span></label>
            <input v-model="form.name" class="input w-full text-sm" placeholder="Group name" />
          </div>
          <div v-if="modalMode === 'create'">
            <label class="block text-xs text-s1-muted mb-1">Site <span class="text-s1-danger">*</span></label>
            <select v-model="form.siteId" class="input w-full text-sm">
              <option v-for="s in sites" :key="s.id" :value="s.id">{{ s.name }}</option>
            </select>
          </div>
          <div>
            <label class="block text-xs text-s1-muted mb-1">Type</label>
            <select v-model="form.type" class="input w-full text-sm">
              <option value="static">Static</option>
              <option value="pinned">Pinned</option>
            </select>
          </div>
          <div>
            <label class="block text-xs text-s1-muted mb-1">Description</label>
            <input v-model="form.description" class="input w-full text-sm" placeholder="Optional" />
          </div>
          <label class="flex items-center gap-2 text-sm text-s1-text cursor-pointer">
            <input type="checkbox" v-model="form.inherits" class="accent-s1-primary" />
            Inherit site policy
          </label>
        </div>

        <p v-if="modalError" class="text-xs text-s1-danger">{{ modalError }}</p>

        <div class="flex justify-end gap-2 pt-1">
          <button @click="closeModal" class="btn-secondary text-sm px-3 py-1.5">Cancel</button>
          <button @click="saveModal" :disabled="modalSaving" class="btn-primary text-sm px-3 py-1.5 disabled:opacity-50">
            {{ modalSaving ? 'Saving…' : 'Save' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
