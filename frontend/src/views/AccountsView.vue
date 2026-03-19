<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { Pencil, Plus, X } from 'lucide-vue-next'
import { accountsApi } from '../api/misc'
import LoadingSkeleton from '../components/shared/LoadingSkeleton.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import type { Account } from '../types'

const items = ref<Account[]>([])
const total = ref(0)
const loading = ref(true)

async function fetchList(): Promise<void> {
  loading.value = true
  try {
    const res = await accountsApi.list({ limit: 100 })
    items.value = res.data
    total.value = res.pagination?.totalItems ?? res.data.length
  } finally {
    loading.value = false
  }
}

onMounted(fetchList)

// ── Modal state ───────────────────────────────────────────────────────────────

type ModalMode = 'create' | 'edit' | null

const modalMode = ref<ModalMode>(null)
const modalSaving = ref(false)
const modalError = ref('')
const editingId = ref<string | null>(null)

const form = reactive({
  name: '',
  accountType: 'Trial',
  expiration: '',
})

function openCreate(): void {
  modalMode.value = 'create'
  editingId.value = null
  modalError.value = ''
  form.name = ''
  form.accountType = 'Trial'
  form.expiration = ''
}

function openEdit(account: Account): void {
  modalMode.value = 'edit'
  editingId.value = account.id
  modalError.value = ''
  form.name = account.name
  form.accountType = account.accountType
  form.expiration = account.expiration ?? ''
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
    const payload: Record<string, unknown> = {
      name: form.name.trim(),
      accountType: form.accountType,
    }
    if (form.expiration) payload.expiration = form.expiration

    if (modalMode.value === 'create') {
      await accountsApi.create(payload)
    } else if (modalMode.value === 'edit' && editingId.value) {
      await accountsApi.update(editingId.value, payload)
    }
    closeModal()
    await fetchList()
  } catch {
    modalError.value = 'Save failed.'
  } finally {
    modalSaving.value = false
  }
}

const STATE_COLOR: Record<string, string> = {
  active: 'text-s1-success',
  inactive: 'text-s1-muted',
  expired: 'text-s1-danger',
}
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-s1-text">Accounts</h1>
        <p class="text-s1-muted text-sm">{{ total }} accounts</p>
      </div>
      <button @click="openCreate" class="btn-primary flex items-center gap-1.5 text-sm px-3 py-1.5">
        <Plus class="w-4 h-4" /> New Account
      </button>
    </div>

    <div class="card overflow-hidden">
      <div v-if="loading"><LoadingSkeleton :rows="3" /></div>
      <EmptyState v-else-if="!items.length" title="No accounts" description="No accounts configured" />
      <table v-else class="w-full text-sm">
        <thead class="border-b border-s1-border">
          <tr class="text-left text-xs text-s1-muted uppercase tracking-wide">
            <th class="px-5 py-3">Name</th>
            <th class="px-5 py-3">State</th>
            <th class="px-5 py-3">Type</th>
            <th class="px-5 py-3">Sites</th>
            <th class="px-5 py-3">Agents</th>
            <th class="px-5 py-3">Users</th>
            <th class="px-5 py-3">Created</th>
            <th class="px-5 py-3"></th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="account in items" :key="account.id"
            class="border-b border-s1-border/50 hover:bg-s1-hover transition-colors"
          >
            <td class="px-5 py-3">
              <div class="text-s1-text font-medium">{{ account.name }}</div>
              <div class="text-xs text-s1-muted font-mono">{{ account.id }}</div>
            </td>
            <td class="px-5 py-3">
              <span :class="STATE_COLOR[account.state] ?? 'text-s1-muted'" class="font-medium capitalize text-xs">
                {{ account.state }}
              </span>
            </td>
            <td class="px-5 py-3 text-s1-muted capitalize">{{ account.accountType }}</td>
            <td class="px-5 py-3 text-s1-text">{{ account.numberOfSites }}</td>
            <td class="px-5 py-3 text-s1-text">{{ account.activeAgents }} / {{ account.numberOfAgents }}</td>
            <td class="px-5 py-3 text-s1-text">{{ account.numberOfUsers }}</td>
            <td class="px-5 py-3 text-s1-muted text-xs">{{ account.createdAt?.slice(0, 10) }}</td>
            <td class="px-5 py-3">
              <button
                @click="openEdit(account)"
                class="text-s1-muted hover:text-s1-primary transition-colors"
                title="Edit account"
              >
                <Pencil class="w-3.5 h-3.5" />
              </button>
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
          <h2 class="text-lg font-bold text-s1-text">{{ modalMode === 'create' ? 'New Account' : 'Edit Account' }}</h2>
          <button @click="closeModal" class="text-s1-muted hover:text-s1-text"><X class="w-5 h-5" /></button>
        </div>

        <div class="space-y-3">
          <div>
            <label class="block text-xs text-s1-muted mb-1">Name <span class="text-s1-danger">*</span></label>
            <input v-model="form.name" class="input w-full text-sm" placeholder="Account name" />
          </div>
          <div>
            <label class="block text-xs text-s1-muted mb-1">Account Type</label>
            <select v-model="form.accountType" class="input w-full text-sm">
              <option value="Trial">Trial</option>
              <option value="Paid">Paid</option>
            </select>
          </div>
          <div>
            <label class="block text-xs text-s1-muted mb-1">Expiration (optional)</label>
            <input v-model="form.expiration" type="datetime-local" class="input w-full text-sm" />
          </div>
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
