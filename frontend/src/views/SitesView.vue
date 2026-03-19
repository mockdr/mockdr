<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { RefreshCw, Clock, Pencil, Trash2, Plus, X, Check } from 'lucide-vue-next'
import { sitesApi } from '../api/misc'
import LoadingSkeleton from '../components/shared/LoadingSkeleton.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import type { Site } from '../types'

const items = ref<Site[]>([])
const total = ref(0)
const loading = ref(true)
const actionId = ref<string | null>(null)

// ── Modal state ───────────────────────────────────────────────────────────────

type ModalMode = 'create' | 'edit' | null

const modalMode = ref<ModalMode>(null)
const modalSaving = ref(false)
const modalError = ref('')
const editingId = ref<string | null>(null)

const form = reactive({
  name: '',
  accountId: '',
  siteType: 'Paid',
  suite: 'Complete',
  sku: 'Complete',
  totalLicenses: 100,
  description: '',
  unlimitedLicenses: false,
})

function openCreate(): void {
  modalMode.value = 'create'
  editingId.value = null
  modalError.value = ''
  form.name = ''
  form.accountId = items.value[0]?.accountId ?? ''
  form.siteType = 'Paid'
  form.suite = 'Complete'
  form.sku = 'Complete'
  form.totalLicenses = 100
  form.description = ''
  form.unlimitedLicenses = false
}

function openEdit(site: Site): void {
  modalMode.value = 'edit'
  editingId.value = site.id
  modalError.value = ''
  form.name = site.name
  form.accountId = site.accountId
  form.siteType = site.siteType
  form.suite = site.suite ?? 'Complete'
  form.sku = site.sku ?? 'Complete'
  form.totalLicenses = site.totalLicenses ?? 100
  form.description = site.description ?? ''
  form.unlimitedLicenses = site.unlimitedLicenses ?? false
}

function closeModal(): void {
  modalMode.value = null
  editingId.value = null
  modalError.value = ''
}

async function saveModal(): Promise<void> {
  modalSaving.value = true
  if (!form.name.trim()) { modalError.value = 'Name is required'; modalSaving.value = false; return }
  modalError.value = ''
  try {
    if (modalMode.value === 'create') {
      await sitesApi.create({
        name: form.name.trim(),
        accountId: form.accountId,
        siteType: form.siteType,
        suite: form.suite,
        sku: form.sku,
        totalLicenses: Number(form.totalLicenses),
        description: form.description || undefined,
        unlimitedLicenses: form.unlimitedLicenses,
      })
    } else if (modalMode.value === 'edit' && editingId.value) {
      await sitesApi.update(editingId.value, {
        name: form.name.trim(),
        siteType: form.siteType,
        suite: form.suite,
        sku: form.sku,
        totalLicenses: Number(form.totalLicenses),
        description: form.description || undefined,
        unlimitedLicenses: form.unlimitedLicenses,
      })
    }
    closeModal()
    await fetchList()
  } catch {
    modalError.value = 'Save failed. Check required fields.'
  } finally {
    modalSaving.value = false
  }
}

// ── Lifecycle actions ─────────────────────────────────────────────────────────

async function fetchList(): Promise<void> {
  loading.value = true
  try {
    const res = await sitesApi.list({ limit: 100 })
    items.value = res.data.sites
    total.value = res.pagination?.totalItems ?? res.data.sites.length
  } finally {
    loading.value = false
  }
}

async function reactivate(site: Site): Promise<void> {
  actionId.value = site.id
  try {
    const res = await sitesApi.reactivate(site.id)
    const idx = items.value.findIndex(s => s.id === site.id)
    if (idx !== -1) items.value[idx] = res.data
  } finally {
    actionId.value = null
  }
}

async function expire(site: Site): Promise<void> {
  actionId.value = site.id
  try {
    await sitesApi.expire(site.id)
    const idx = items.value.findIndex(s => s.id === site.id)
    if (idx !== -1) items.value[idx] = { ...items.value[idx], state: 'expired' }
  } finally {
    actionId.value = null
  }
}

const deletingId = ref<string | null>(null)
const confirmDeleteId = ref<string | null>(null)

function requestDelete(site: Site): void {
  confirmDeleteId.value = site.id
}

async function confirmDelete(site: Site): Promise<void> {
  deletingId.value = site.id
  confirmDeleteId.value = null
  try {
    await sitesApi.delete(site.id)
    items.value = items.value.filter(s => s.id !== site.id)
    total.value -= 1
  } finally {
    deletingId.value = null
  }
}

onMounted(fetchList)

const STATUS_COLOR: Record<string, string> = {
  active: 'text-s1-success',
  inactive: 'text-s1-muted',
  expired: 'text-s1-danger',
}
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-s1-text">Sites</h1>
        <p class="text-s1-muted text-sm">{{ total }} sites</p>
      </div>
      <button @click="openCreate" class="btn-primary flex items-center gap-1.5 text-sm px-3 py-1.5">
        <Plus class="w-4 h-4" /> New Site
      </button>
    </div>

    <div class="card overflow-hidden">
      <div v-if="loading"><LoadingSkeleton :rows="5" /></div>
      <EmptyState v-else-if="!items.length" title="No sites" description="No sites configured" />
      <table v-else class="w-full text-sm">
        <thead class="border-b border-s1-border">
          <tr class="text-left text-xs text-s1-muted uppercase tracking-wide">
            <th class="px-5 py-3">Name</th>
            <th class="px-5 py-3">Account</th>
            <th class="px-5 py-3">State</th>
            <th class="px-5 py-3">Licenses</th>
            <th class="px-5 py-3">Site Type</th>
            <th class="px-5 py-3">Created</th>
            <th class="px-5 py-3"></th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="site in items" :key="site.id"
            class="border-b border-s1-border/50 hover:bg-s1-hover transition-colors"
          >
            <td class="px-5 py-3">
              <div class="text-s1-text font-medium">{{ site.name }}</div>
              <div class="text-xs text-s1-muted font-mono">{{ site.id }}</div>
            </td>
            <td class="px-5 py-3 text-s1-muted">{{ site.accountName }}</td>
            <td class="px-5 py-3">
              <span :class="STATUS_COLOR[site.state] ?? 'text-s1-muted'" class="font-medium capitalize text-xs">
                {{ site.state }}
              </span>
            </td>
            <td class="px-5 py-3 text-s1-text">{{ site.activeLicenses ?? '—' }}</td>
            <td class="px-5 py-3 text-s1-muted capitalize">{{ site.siteType }}</td>
            <td class="px-5 py-3 text-s1-muted text-xs">{{ site.createdAt?.slice(0, 10) }}</td>
            <td class="px-5 py-3">
              <div class="flex items-center gap-2">
                <button
                  v-if="site.state === 'expired'"
                  @click="reactivate(site)"
                  :disabled="actionId === site.id"
                  class="flex items-center gap-1 text-xs text-s1-success hover:opacity-80 disabled:opacity-40 transition-opacity"
                  title="Reactivate"
                >
                  <RefreshCw class="w-3.5 h-3.5" /> Reactivate
                </button>
                <button
                  v-if="site.state === 'active'"
                  @click="expire(site)"
                  :disabled="actionId === site.id"
                  class="flex items-center gap-1 text-xs text-s1-warning hover:opacity-80 disabled:opacity-40 transition-opacity"
                  title="Expire now"
                >
                  <Clock class="w-3.5 h-3.5" /> Expire
                </button>
                <button
                  @click="openEdit(site)"
                  class="text-s1-muted hover:text-s1-primary transition-colors"
                  title="Edit site"
                >
                  <Pencil class="w-3.5 h-3.5" />
                </button>
                <template v-if="!site.isDefault">
                  <button
                    v-if="confirmDeleteId !== site.id"
                    @click="requestDelete(site)"
                    :disabled="deletingId === site.id"
                    class="text-s1-muted hover:text-s1-danger transition-colors disabled:opacity-40"
                    title="Delete site"
                  >
                    <Trash2 class="w-3.5 h-3.5" />
                  </button>
                  <template v-else>
                    <button @click="confirmDelete(site)" class="text-xs text-s1-danger hover:opacity-80 flex items-center gap-0.5">
                      <Check class="w-3.5 h-3.5" /> Confirm
                    </button>
                    <button @click="confirmDeleteId = null" class="text-xs text-s1-muted hover:opacity-80">
                      <X class="w-3.5 h-3.5" />
                    </button>
                  </template>
                </template>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Create / Edit Modal -->
    <div
      v-if="modalMode"
      role="dialog"
      aria-modal="true"
      :aria-label="modalMode === 'create' ? 'Create new site' : 'Edit site'"
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
      @click.self="closeModal"
    >
      <div class="card w-full max-w-md p-6 space-y-4">
        <div class="flex items-center justify-between">
          <h2 class="text-lg font-bold text-s1-text">{{ modalMode === 'create' ? 'New Site' : 'Edit Site' }}</h2>
          <button @click="closeModal" aria-label="Close dialog" class="text-s1-muted hover:text-s1-text"><X class="w-5 h-5" /></button>
        </div>

        <div class="space-y-3">
          <div>
            <label for="site-name" class="block text-xs text-s1-muted mb-1">Name <span class="text-s1-danger">*</span></label>
            <input id="site-name" v-model="form.name" class="input w-full text-sm" placeholder="Site name" />
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label for="site-type" class="block text-xs text-s1-muted mb-1">Site Type</label>
              <select id="site-type" v-model="form.siteType" class="input w-full text-sm">
                <option>Paid</option>
                <option>Trial</option>
              </select>
            </div>
            <div>
              <label for="site-suite" class="block text-xs text-s1-muted mb-1">Suite</label>
              <select id="site-suite" v-model="form.suite" class="input w-full text-sm">
                <option>Complete</option>
                <option>Core</option>
              </select>
            </div>
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label for="site-sku" class="block text-xs text-s1-muted mb-1">SKU</label>
              <select id="site-sku" v-model="form.sku" class="input w-full text-sm">
                <option>Complete</option>
                <option>Control</option>
              </select>
            </div>
            <div>
              <label for="site-licenses" class="block text-xs text-s1-muted mb-1">Total Licenses</label>
              <input id="site-licenses" v-model.number="form.totalLicenses" type="number" min="0" class="input w-full text-sm" />
            </div>
          </div>
          <div>
            <label for="site-description" class="block text-xs text-s1-muted mb-1">Description</label>
            <input id="site-description" v-model="form.description" class="input w-full text-sm" placeholder="Optional" />
          </div>
          <label class="flex items-center gap-2 text-sm text-s1-text cursor-pointer">
            <input type="checkbox" v-model="form.unlimitedLicenses" class="accent-s1-primary" />
            Unlimited licenses
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
