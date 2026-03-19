<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { Pencil, Plus, Trash2, X } from 'lucide-vue-next'
import { firewallApi, sitesApi } from '../api/misc'
import LoadingSkeleton from '../components/shared/LoadingSkeleton.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import type { FirewallRule, Site } from '../types'

const items   = ref<FirewallRule[]>([])
const total   = ref(0)
const loading = ref(true)
const sites   = ref<Site[]>([])

onMounted(async () => {
  try {
    const [rulesRes, sitesRes] = await Promise.all([
      firewallApi.list({ limit: 200 }),
      sitesApi.list({ limit: 100 }),
    ])
    items.value = rulesRes.data
    total.value = rulesRes.pagination?.totalItems ?? rulesRes.data.length
    sites.value = sitesRes.data.sites
  } finally {
    loading.value = false
  }
})

// ── Modal ──────────────────────────────────────────────────────────────────────

type ModalMode = 'create' | 'edit' | null

const modalMode   = ref<ModalMode>(null)
const modalSaving = ref(false)
const modalError  = ref('')
const editingId   = ref<string | null>(null)

const form = reactive({
  name: '',
  description: '',
  action: 'Allow',
  direction: 'any',
  status: 'Enabled',
  protocol: '',
  osTypes: ['windows'] as string[],
  siteId: '',
  remoteHostType: 'any',
  remoteHostValues: '',    // comma-separated when specific
  remotePortType: 'any',
  remotePortValues: '',
})

function openCreate(): void {
  modalMode.value = 'create'
  editingId.value = null
  modalError.value = ''
  form.name = ''
  form.description = ''
  form.action = 'Allow'
  form.direction = 'any'
  form.status = 'Enabled'
  form.protocol = ''
  form.osTypes = ['windows']
  form.siteId = sites.value[0]?.id ?? ''
  form.remoteHostType = 'any'
  form.remoteHostValues = ''
  form.remotePortType = 'any'
  form.remotePortValues = ''
}

function openEdit(rule: FirewallRule): void {
  modalMode.value = 'edit'
  editingId.value = rule.id
  modalError.value = ''
  form.name = rule.name
  form.description = rule.description ?? ''
  form.action = rule.action
  form.direction = rule.direction
  form.status = rule.status
  form.protocol = rule.protocol ?? ''
  form.osTypes = rule.osTypes?.length ? rule.osTypes : ['windows']
  form.siteId = ''
  const rh = Array.isArray(rule.remoteHosts) ? rule.remoteHosts[0] : null
  form.remoteHostType = rh?.type ?? 'any'
  form.remoteHostValues = (rh?.values as string[] ?? []).join(', ')
  const rp = rule.remotePort
  form.remotePortType = rp?.type ?? 'any'
  form.remotePortValues = (rp?.values as string[] ?? []).join(', ')
}

function closeModal(): void {
  modalMode.value = null
  editingId.value = null
  modalError.value = ''
}

function buildRemoteHosts() {
  return [{
    type: form.remoteHostType,
    values: form.remoteHostType === 'any' ? [] : form.remoteHostValues.split(',').map(s => s.trim()).filter(Boolean),
  }]
}

function buildPort(type: string, values: string) {
  return {
    type,
    values: type === 'any' ? [] : values.split(',').map(s => s.trim()).filter(Boolean),
  }
}

async function saveModal(): Promise<void> {
  modalSaving.value = true
  if (!form.name.trim()) { modalError.value = 'Name is required'; modalSaving.value = false; return }
  modalError.value = ''
  try {
    const data: Record<string, unknown> = {
      name: form.name.trim(),
      description: form.description || null,
      action: form.action,
      direction: form.direction,
      status: form.status,
      protocol: form.protocol || null,
      osTypes: form.osTypes,
      remoteHosts: buildRemoteHosts(),
      remotePort: buildPort(form.remotePortType, form.remotePortValues),
      location: { type: 'all', values: [] },
    }

    if (modalMode.value === 'create') {
      const filter = form.siteId ? { siteIds: [form.siteId] } : {}
      const res = await firewallApi.create(data, filter)
      items.value.push(res.data)
      total.value += 1
    } else if (editingId.value) {
      const res = await firewallApi.update(editingId.value, data)
      const idx = items.value.findIndex(r => r.id === editingId.value)
      if (idx !== -1) items.value[idx] = res.data
    }
    closeModal()
  } catch {
    modalError.value = 'Save failed.'
  } finally {
    modalSaving.value = false
  }
}

// ── Delete ────────────────────────────────────────────────────────────────────

const confirmDeleteId = ref<string | null>(null)
const deletingId      = ref<string | null>(null)

async function confirmDelete(rule: FirewallRule): Promise<void> {
  deletingId.value = rule.id
  confirmDeleteId.value = null
  try {
    await firewallApi.delete(rule.id)
    items.value = items.value.filter(r => r.id !== rule.id)
    total.value -= 1
  } finally {
    deletingId.value = null
  }
}

// ── Display ────────────────────────────────────────────────────────────────────

const ACTION_COLOR: Record<string, string> = {
  Allow: 'text-s1-success',
  Block: 'text-s1-danger',
  allow: 'text-s1-success',
  block: 'text-s1-danger',
}

const DIRECTION_ICON: Record<string, string> = { inbound: '↓', outbound: '↑', any: '↕', both: '↕' }

function remoteHostLabel(rule: FirewallRule): string {
  const rh = Array.isArray(rule.remoteHosts) ? rule.remoteHosts[0] : null
  if (!rh || rh.type === 'any') return 'Any'
  const vals = rh.values as string[]
  return vals.length ? vals.slice(0, 2).join(', ') + (vals.length > 2 ? '…' : '') : 'Any'
}

function remotePortLabel(rule: FirewallRule): string {
  const rp = rule.remotePort
  if (!rp || rp.type === 'any') return 'Any'
  const vals = rp.values as string[]
  return vals.length ? vals.join(', ') : 'Any'
}

function toggleOsType(os: string): void {
  const i = form.osTypes.indexOf(os)
  if (i === -1) form.osTypes.push(os)
  else if (form.osTypes.length > 1) form.osTypes.splice(i, 1)
}
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-s1-text">Firewall Rules</h1>
        <p class="text-s1-muted text-sm">{{ total }} rules</p>
      </div>
      <button @click="openCreate" class="btn-primary flex items-center gap-1.5 text-sm px-3 py-1.5">
        <Plus class="w-4 h-4" /> New Rule
      </button>
    </div>

    <div class="card overflow-hidden">
      <div v-if="loading"><LoadingSkeleton :rows="6" /></div>
      <EmptyState v-else-if="!items.length" title="No firewall rules" description="No rules configured" />
      <table v-else class="w-full text-sm">
        <thead class="border-b border-s1-border">
          <tr class="text-left text-xs text-s1-muted uppercase tracking-wide">
            <th class="px-5 py-3">#</th>
            <th class="px-5 py-3">Name</th>
            <th class="px-5 py-3">Action</th>
            <th class="px-5 py-3">Direction</th>
            <th class="px-5 py-3">Protocol</th>
            <th class="px-5 py-3">Remote Host</th>
            <th class="px-5 py-3">Port</th>
            <th class="px-5 py-3">Status</th>
            <th class="px-5 py-3"></th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="rule in items" :key="rule.id"
            class="border-b border-s1-border/50 hover:bg-s1-hover transition-colors"
          >
            <td class="px-5 py-3 text-s1-muted text-xs">{{ rule.order }}</td>
            <td class="px-5 py-3">
              <div class="text-s1-text font-medium">{{ rule.name }}</div>
              <div v-if="rule.description" class="text-xs text-s1-muted">{{ rule.description }}</div>
            </td>
            <td class="px-5 py-3">
              <span :class="ACTION_COLOR[rule.action] ?? 'text-s1-muted'" class="font-semibold capitalize text-xs">
                {{ rule.action }}
              </span>
            </td>
            <td class="px-5 py-3 text-s1-muted">
              {{ DIRECTION_ICON[rule.direction] ?? '' }} {{ rule.direction }}
            </td>
            <td class="px-5 py-3 text-s1-muted uppercase text-xs">{{ rule.protocol || 'Any' }}</td>
            <td class="px-5 py-3 text-s1-muted font-mono text-xs">{{ remoteHostLabel(rule) }}</td>
            <td class="px-5 py-3 text-s1-muted text-xs">{{ remotePortLabel(rule) }}</td>
            <td class="px-5 py-3">
              <span
                :class="rule.status === 'Enabled' ? 'text-s1-success' : 'text-s1-muted'"
                class="text-xs"
              >{{ rule.status }}</span>
            </td>
            <td class="px-5 py-3">
              <div class="flex items-center gap-2">
                <button
                  v-if="rule.editable !== false"
                  @click="openEdit(rule)"
                  class="text-s1-muted hover:text-s1-primary transition-colors"
                  title="Edit"
                ><Pencil class="w-3.5 h-3.5" /></button>

                <button
                  v-if="confirmDeleteId !== rule.id && rule.editable !== false"
                  @click="confirmDeleteId = rule.id"
                  :disabled="deletingId === rule.id"
                  class="text-s1-muted hover:text-s1-danger transition-colors disabled:opacity-40"
                  title="Delete"
                ><Trash2 class="w-3.5 h-3.5" /></button>
                <template v-else-if="confirmDeleteId === rule.id">
                  <button @click="confirmDelete(rule)" class="text-xs text-s1-danger hover:opacity-80">Confirm</button>
                  <button @click="confirmDeleteId = null" class="text-xs text-s1-muted hover:opacity-80">
                    <X class="w-3.5 h-3.5" />
                  </button>
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
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
      @click.self="closeModal"
    >
      <div class="card w-full max-w-lg p-6 space-y-4 max-h-[90vh] overflow-y-auto">
        <div class="flex items-center justify-between">
          <h2 class="text-lg font-bold text-s1-text">{{ modalMode === 'create' ? 'New Rule' : 'Edit Rule' }}</h2>
          <button @click="closeModal" class="text-s1-muted hover:text-s1-text"><X class="w-5 h-5" /></button>
        </div>

        <div class="space-y-3">
          <!-- Name -->
          <div>
            <label class="block text-xs text-s1-muted mb-1">Name <span class="text-s1-danger">*</span></label>
            <input v-model="form.name" class="input w-full text-sm" placeholder="Rule name" />
          </div>

          <!-- Description -->
          <div>
            <label class="block text-xs text-s1-muted mb-1">Description</label>
            <input v-model="form.description" class="input w-full text-sm" placeholder="Optional" />
          </div>

          <!-- Action + Status row -->
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block text-xs text-s1-muted mb-1">Action</label>
              <select v-model="form.action" class="input w-full text-sm">
                <option value="Allow">Allow</option>
                <option value="Block">Block</option>
              </select>
            </div>
            <div>
              <label class="block text-xs text-s1-muted mb-1">Status</label>
              <select v-model="form.status" class="input w-full text-sm">
                <option value="Enabled">Enabled</option>
                <option value="Disabled">Disabled</option>
              </select>
            </div>
          </div>

          <!-- Direction + Protocol row -->
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block text-xs text-s1-muted mb-1">Direction</label>
              <select v-model="form.direction" class="input w-full text-sm">
                <option value="any">Any</option>
                <option value="inbound">Inbound</option>
                <option value="outbound">Outbound</option>
              </select>
            </div>
            <div>
              <label class="block text-xs text-s1-muted mb-1">Protocol</label>
              <select v-model="form.protocol" class="input w-full text-sm">
                <option value="">Any</option>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
              </select>
            </div>
          </div>

          <!-- OS Types -->
          <div>
            <label class="block text-xs text-s1-muted mb-1">OS Types</label>
            <div class="flex gap-2">
              <button
                v-for="os in ['windows', 'macos', 'linux']" :key="os"
                @click="toggleOsType(os)"
                :class="form.osTypes.includes(os) ? 'bg-s1-primary/15 text-s1-primary border-s1-primary/40' : 'border-s1-border text-s1-muted'"
                class="text-xs px-2.5 py-1 rounded border transition-colors capitalize"
              >{{ os }}</button>
            </div>
          </div>

          <!-- Remote Host -->
          <div>
            <label class="block text-xs text-s1-muted mb-1">Remote Host</label>
            <div class="flex gap-2">
              <select v-model="form.remoteHostType" class="input text-sm w-32">
                <option value="any">Any</option>
                <option value="addresses">Addresses</option>
                <option value="cidr">CIDR</option>
                <option value="fqdn">FQDN</option>
              </select>
              <input
                v-if="form.remoteHostType !== 'any'"
                v-model="form.remoteHostValues"
                class="input text-sm flex-1"
                placeholder="comma-separated values"
              />
            </div>
          </div>

          <!-- Remote Port -->
          <div>
            <label class="block text-xs text-s1-muted mb-1">Remote Port</label>
            <div class="flex gap-2">
              <select v-model="form.remotePortType" class="input text-sm w-32">
                <option value="any">Any</option>
                <option value="ports">Ports</option>
                <option value="range">Range</option>
              </select>
              <input
                v-if="form.remotePortType !== 'any'"
                v-model="form.remotePortValues"
                class="input text-sm flex-1"
                placeholder="e.g. 80, 443"
              />
            </div>
          </div>

          <!-- Site (create only) -->
          <div v-if="modalMode === 'create' && sites.length">
            <label class="block text-xs text-s1-muted mb-1">Site scope (optional)</label>
            <select v-model="form.siteId" class="input w-full text-sm">
              <option value="">Global</option>
              <option v-for="s in sites" :key="s.id" :value="s.id">{{ s.name }}</option>
            </select>
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
