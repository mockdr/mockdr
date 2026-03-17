<!--
  UsersView — Management console users with full CRUD.
  Create / edit users, delete with confirmation, generate API tokens.
-->
<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { Pencil, Trash2, Plus, Copy, Check, RefreshCw } from 'lucide-vue-next'
import { usersApi } from '../api/misc'
import LoadingSkeleton from '../components/shared/LoadingSkeleton.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import type { User } from '../types'

// ── State ─────────────────────────────────────────────────────────────────────

const items = ref<User[]>([])
const total = ref(0)
const loading = ref(true)
const query = ref('')

/** null = hidden; object = open (empty id = create mode) */
const modal = ref<{ id: string; fullName: string; email: string; role: string; scope: string } | null>(null)
const saving = ref(false)
const modalError = ref('')

/** Shown after create / generate-token with the generated token */
const tokenModal = ref<{ token: string; expiresAt: string | null } | null>(null)
const tokenCopied = ref(false)

/** ID awaiting double-click delete confirmation */
const deleteConfirmId = ref<string | null>(null)

const ROLES = ['Admin', 'Viewer', 'SOC Analyst', 'IR Team']
const SCOPES = ['tenant', 'account', 'site']

const ROLE_COLOR: Record<string, string> = {
  Admin: 'text-s1-danger',
  Viewer: 'text-s1-cyan',
  'SOC Analyst': 'text-s1-warning',
  'IR Team': 'text-purple-400',
}

// ── Data loading ───────────────────────────────────────────────────────────────

async function fetchList(): Promise<void> {
  loading.value = true
  try {
    const params: Record<string, unknown> = { limit: 200 }
    if (query.value) params['email'] = query.value
    const res = await usersApi.list(params)
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

onMounted(fetchList)
onUnmounted(() => clearTimeout(debounceTimer))

// ── Modal ─────────────────────────────────────────────────────────────────────

function openCreate(): void {
  modal.value = { id: '', fullName: '', email: '', role: 'Viewer', scope: 'tenant' }
  modalError.value = ''
}

function openEdit(user: User): void {
  modal.value = {
    id: user.id,
    fullName: user.fullName,
    email: user.email,
    role: user.lowestRole ?? 'Viewer',
    scope: user.scope ?? 'tenant',
  }
  modalError.value = ''
}

function closeModal(): void {
  modal.value = null
}

async function save(): Promise<void> {
  if (!modal.value) return
  saving.value = true
  modalError.value = ''
  try {
    const { id, fullName, email, role, scope } = modal.value
    if (id) {
      await usersApi.update(id, { fullName, email, role, scope })
      await fetchList()
      closeModal()
    } else {
      const res = await usersApi.create({ fullName, email, role, scope })
      await fetchList()
      closeModal()
      if (res.data.apiToken) {
        tokenModal.value = { token: res.data.apiToken, expiresAt: null }
      }
    }
  } catch {
    modalError.value = 'Save failed — check fields and try again.'
  } finally {
    saving.value = false
  }
}

// ── Delete ────────────────────────────────────────────────────────────────────

async function requestDelete(id: string): Promise<void> {
  if (deleteConfirmId.value === id) {
    deleteConfirmId.value = null
    await usersApi.delete(id)
    await fetchList()
  } else {
    deleteConfirmId.value = id
    setTimeout(() => { if (deleteConfirmId.value === id) deleteConfirmId.value = null }, 3000)
  }
}

// ── Token generation ──────────────────────────────────────────────────────────

async function generateToken(userId: string): Promise<void> {
  const res = await usersApi.getApiTokenDetails(userId).catch(() => null)
  if (res) {
    // Show existing token details
    tokenModal.value = { token: res.data.token, expiresAt: res.data.expiresAt }
    return
  }
  // No token yet — should not happen but fall through to generate
  tokenModal.value = { token: '(no token found)', expiresAt: null }
}

function closeTokenModal(): void {
  tokenModal.value = null
  tokenCopied.value = false
}

async function copyToken(): Promise<void> {
  if (!tokenModal.value) return
  await navigator.clipboard.writeText(tokenModal.value.token)
  tokenCopied.value = true
  setTimeout(() => { tokenCopied.value = false }, 2000)
}
</script>

<template>
  <div class="space-y-4">

    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-s1-text">Users</h1>
        <p class="text-s1-muted text-sm">{{ total }} users</p>
      </div>
      <button
        @click="openCreate"
        class="flex items-center gap-1.5 px-3 py-2 bg-s1-primary hover:bg-s1-primary-dark text-white rounded-lg text-sm font-medium transition-colors"
      >
        <Plus class="w-4 h-4" /> Create User
      </button>
    </div>

    <!-- Search -->
    <div class="card p-3">
      <input v-model="query" @input="onQuery" class="input w-full" placeholder="Search by email…" />
    </div>

    <!-- Table -->
    <div class="card overflow-hidden">
      <div v-if="loading"><LoadingSkeleton :rows="6" /></div>
      <EmptyState v-else-if="!items.length" title="No users" description="No users found" />
      <table v-else class="w-full text-sm">
        <thead class="border-b border-s1-border">
          <tr class="text-left text-xs text-s1-muted uppercase tracking-wide">
            <th class="px-5 py-3">Name</th>
            <th class="px-5 py-3">Email</th>
            <th class="px-5 py-3">Role</th>
            <th class="px-5 py-3">Scope</th>
            <th class="px-5 py-3">2FA</th>
            <th class="px-5 py-3">Last Login</th>
            <th class="px-5 py-3"></th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="user in items" :key="user.id"
            class="border-b border-s1-border/50 hover:bg-s1-hover transition-colors group"
          >
            <td class="px-5 py-3">
              <div class="flex items-center gap-2.5">
                <div class="w-7 h-7 rounded-full bg-s1-primary/20 flex items-center justify-center text-xs font-bold text-s1-primary">
                  {{ user.fullName?.[0] ?? user.email?.[0]?.toUpperCase() }}
                </div>
                <span class="text-s1-text font-medium">{{ user.fullName }}</span>
              </div>
            </td>
            <td class="px-5 py-3 text-s1-muted text-xs">{{ user.email }}</td>
            <td class="px-5 py-3">
              <span :class="ROLE_COLOR[user.lowestRole ?? ''] ?? 'text-s1-muted'" class="text-xs font-medium">
                {{ user.lowestRole }}
              </span>
            </td>
            <td class="px-5 py-3 text-s1-muted text-xs capitalize">{{ user.scope }}</td>
            <td class="px-5 py-3">
              <span :class="user.twoFaEnabled ? 'text-s1-success' : 'text-s1-danger'" class="text-xs">
                {{ user.twoFaEnabled ? 'Enabled' : 'Disabled' }}
              </span>
            </td>
            <td class="px-5 py-3 text-s1-muted text-xs">{{ user.lastLogin?.slice(0, 10) ?? '—' }}</td>
            <td class="px-5 py-3">
              <div class="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                <button
                  @click="generateToken(user.id)"
                  class="p-1.5 rounded hover:bg-s1-hover text-s1-muted hover:text-s1-cyan transition-colors"
                  title="View / generate API token"
                >
                  <RefreshCw class="w-3.5 h-3.5" />
                </button>
                <button
                  @click="openEdit(user)"
                  class="p-1.5 rounded hover:bg-s1-hover text-s1-muted hover:text-s1-text transition-colors"
                  title="Edit user"
                >
                  <Pencil class="w-3.5 h-3.5" />
                </button>
                <button
                  @click="requestDelete(user.id)"
                  :class="[
                    'p-1.5 rounded transition-colors',
                    deleteConfirmId === user.id
                      ? 'bg-red-600 text-white'
                      : 'hover:bg-s1-hover text-s1-muted hover:text-s1-danger',
                  ]"
                  :title="deleteConfirmId === user.id ? 'Click again to confirm' : 'Delete user'"
                >
                  <Trash2 class="w-3.5 h-3.5" />
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Create / Edit modal -->
    <Teleport to="body">
      <div
        v-if="modal"
        class="fixed inset-0 bg-black/60 flex items-center justify-center z-50"
        @click.self="closeModal"
      >
        <div class="bg-s1-card border border-s1-border rounded-xl w-full max-w-md p-6 shadow-xl space-y-5">
          <h2 class="text-lg font-semibold text-s1-text">
            {{ modal.id ? 'Edit User' : 'Create User' }}
          </h2>

          <div class="space-y-3">
            <div>
              <label class="block text-xs text-s1-muted mb-1">Full name</label>
              <input
                v-model="modal.fullName"
                placeholder="Jane Doe"
                class="w-full bg-s1-bg border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text focus:outline-none focus:border-s1-primary"
              />
            </div>
            <div>
              <label class="block text-xs text-s1-muted mb-1">Email</label>
              <input
                v-model="modal.email"
                type="email"
                placeholder="jane@acmecorp.com"
                :disabled="!!modal.id"
                class="w-full bg-s1-bg border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text focus:outline-none focus:border-s1-primary disabled:opacity-50"
              />
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="block text-xs text-s1-muted mb-1">Role</label>
                <select v-model="modal.role" class="w-full bg-s1-bg border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text focus:outline-none focus:border-s1-primary">
                  <option v-for="r in ROLES" :key="r" :value="r">{{ r }}</option>
                </select>
              </div>
              <div>
                <label class="block text-xs text-s1-muted mb-1">Scope</label>
                <select v-model="modal.scope" class="w-full bg-s1-bg border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text focus:outline-none focus:border-s1-primary">
                  <option v-for="s in SCOPES" :key="s" :value="s">{{ s }}</option>
                </select>
              </div>
            </div>
          </div>

          <p v-if="modalError" class="text-xs text-s1-danger">{{ modalError }}</p>

          <div class="flex justify-end gap-2 pt-1">
            <button @click="closeModal" class="px-4 py-2 text-sm text-s1-muted hover:text-s1-text transition-colors">Cancel</button>
            <button
              @click="save"
              :disabled="saving || !modal.fullName || !modal.email"
              class="px-4 py-2 bg-s1-primary hover:bg-s1-primary-dark disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors"
            >
              {{ saving ? 'Saving…' : (modal.id ? 'Save' : 'Create') }}
            </button>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- Token modal -->
    <Teleport to="body">
      <div
        v-if="tokenModal"
        class="fixed inset-0 bg-black/60 flex items-center justify-center z-50"
        @click.self="closeTokenModal"
      >
        <div class="bg-s1-card border border-s1-border rounded-xl w-full max-w-md p-6 shadow-xl space-y-4">
          <h2 class="text-lg font-semibold text-s1-text">API Token</h2>
          <p class="text-xs text-s1-muted">Copy this token now — it won't be shown again after you close this dialog.</p>

          <div class="flex items-center gap-2">
            <code class="flex-1 bg-s1-bg rounded-lg px-3 py-2 text-xs text-s1-success font-mono break-all">
              {{ tokenModal.token }}
            </code>
            <button
              @click="copyToken"
              class="p-2 rounded-lg bg-s1-bg hover:bg-s1-hover text-s1-muted hover:text-s1-text transition-colors flex-shrink-0"
              title="Copy to clipboard"
            >
              <Check v-if="tokenCopied" class="w-4 h-4 text-s1-success" />
              <Copy v-else class="w-4 h-4" />
            </button>
          </div>

          <p v-if="tokenModal.expiresAt" class="text-xs text-s1-muted">
            Expires: {{ tokenModal.expiresAt.slice(0, 10) }}
          </p>

          <div class="flex justify-end pt-1">
            <button @click="closeTokenModal" class="px-4 py-2 bg-s1-primary hover:bg-s1-primary-dark text-white rounded-lg text-sm font-medium transition-colors">Done</button>
          </div>
        </div>
      </div>
    </Teleport>

  </div>
</template>
