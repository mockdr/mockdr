<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { Pencil, Plus, Trash2, X } from 'lucide-vue-next'
import { deviceControlApi } from '../api/misc'
import LoadingSkeleton from '../components/shared/LoadingSkeleton.vue'
import EmptyState from '../components/shared/EmptyState.vue'
import type { DeviceControlRule } from '../types'

const items   = ref<DeviceControlRule[]>([])
const total   = ref(0)
const loading = ref(true)

onMounted(async () => {
  try {
    const res = await deviceControlApi.list({ limit: 200 })
    items.value = res.data
    total.value = res.pagination?.totalItems ?? res.data.length
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

const DEVICE_CLASSES = [
  'USB_STORAGE', 'BLUETOOTH', 'PRINTER', 'CAMERA', 'AUDIO',
  'NETWORK', 'THUNDERBOLT', 'SD_CARD',
]

const form = reactive({
  ruleName: '',
  action: 'Allow',
  status: 'Enabled',
  interface: 'USB',
  ruleType: 'class',
  deviceClass: 'USB_STORAGE',
  accessPermission: 'Not-Applicable',
  vendorId: '',
  productId: '',
  deviceId: '',
  uid: '',
})

function openCreate(): void {
  modalMode.value = 'create'
  editingId.value = null
  modalError.value = ''
  form.ruleName = ''
  form.action = 'Allow'
  form.status = 'Enabled'
  form.interface = 'USB'
  form.ruleType = 'class'
  form.deviceClass = 'USB_STORAGE'
  form.accessPermission = 'Not-Applicable'
  form.vendorId = ''
  form.productId = ''
  form.deviceId = ''
  form.uid = ''
}

function openEdit(rule: DeviceControlRule): void {
  modalMode.value = 'edit'
  editingId.value = rule.id
  modalError.value = ''
  form.ruleName = rule.ruleName
  form.action = rule.action
  form.status = rule.status
  form.interface = rule.interface
  form.ruleType = rule.ruleType
  form.deviceClass = rule.deviceClass
  form.accessPermission = rule.accessPermission ?? 'Not-Applicable'
  form.vendorId = rule.vendorId ?? ''
  form.productId = rule.productId ?? ''
  form.deviceId = rule.deviceId ?? ''
  form.uid = rule.uid ?? ''
}

function closeModal(): void {
  modalMode.value = null
  editingId.value = null
  modalError.value = ''
}

async function saveModal(): Promise<void> {
  modalSaving.value = true
  if (!form.ruleName.trim()) { modalError.value = 'Rule name is required'; modalSaving.value = false; return }
  modalError.value = ''
  try {
    const data: Record<string, unknown> = {
      ruleName: form.ruleName.trim(),
      action: form.action,
      status: form.status,
      interface: form.interface,
      ruleType: form.ruleType,
      deviceClass: form.deviceClass,
      accessPermission: form.accessPermission,
      vendorId: form.vendorId || null,
      productId: form.productId || null,
      deviceId: form.deviceId || null,
      uid: form.uid || null,
    }

    if (modalMode.value === 'create') {
      const res = await deviceControlApi.create(data)
      items.value.push(res.data)
      total.value += 1
    } else if (editingId.value) {
      const res = await deviceControlApi.update(editingId.value, data)
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

async function confirmDelete(rule: DeviceControlRule): Promise<void> {
  deletingId.value = rule.id
  confirmDeleteId.value = null
  try {
    await deviceControlApi.delete(rule.id)
    items.value = items.value.filter(r => r.id !== rule.id)
    total.value -= 1
  } finally {
    deletingId.value = null
  }
}

// ── Display ───────────────────────────────────────────────────────────────────

const ACTION_COLOR: Record<string, string> = {
  Allow: 'text-s1-success',
  Block: 'text-s1-danger',
  'Read-Only': 'text-yellow-400',
}
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-s1-text">Device Control</h1>
        <p class="text-s1-muted text-sm">{{ total }} rules</p>
      </div>
      <button @click="openCreate" class="btn-primary flex items-center gap-1.5 text-sm px-3 py-1.5">
        <Plus class="w-4 h-4" /> New Rule
      </button>
    </div>

    <div class="card overflow-hidden">
      <div v-if="loading"><LoadingSkeleton :rows="6" /></div>
      <EmptyState v-else-if="!items.length" title="No device control rules" description="No rules configured" />
      <table v-else class="w-full text-sm">
        <thead class="border-b border-s1-border">
          <tr class="text-left text-xs text-s1-muted uppercase tracking-wide">
            <th class="px-5 py-3">Name</th>
            <th class="px-5 py-3">Device Class</th>
            <th class="px-5 py-3">Interface</th>
            <th class="px-5 py-3">Action</th>
            <th class="px-5 py-3">Access</th>
            <th class="px-5 py-3">Vendor ID</th>
            <th class="px-5 py-3">Status</th>
            <th class="px-5 py-3"></th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="rule in items" :key="rule.id"
            class="border-b border-s1-border/50 hover:bg-s1-hover transition-colors"
          >
            <td class="px-5 py-3">
              <div class="text-s1-text font-medium">{{ rule.ruleName }}</div>
              <div class="text-xs text-s1-muted font-mono">{{ rule.id }}</div>
            </td>
            <td class="px-5 py-3 text-s1-muted capitalize text-xs">{{ rule.deviceClass }}</td>
            <td class="px-5 py-3 text-s1-muted text-xs">{{ rule.interface }}</td>
            <td class="px-5 py-3">
              <span :class="ACTION_COLOR[rule.action] ?? 'text-s1-muted'" class="font-semibold text-xs">
                {{ rule.action }}
              </span>
            </td>
            <td class="px-5 py-3 text-s1-muted text-xs">{{ rule.accessPermission ?? '—' }}</td>
            <td class="px-5 py-3 font-mono text-xs text-s1-muted">{{ rule.vendorId ?? 'Any' }}</td>
            <td class="px-5 py-3">
              <span :class="rule.status === 'Enabled' ? 'text-s1-success' : 'text-s1-muted'" class="text-xs">
                {{ rule.status }}
              </span>
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
          <!-- Rule Name -->
          <div>
            <label class="block text-xs text-s1-muted mb-1">Rule Name <span class="text-s1-danger">*</span></label>
            <input v-model="form.ruleName" class="input w-full text-sm" placeholder="Rule name" />
          </div>

          <!-- Action + Status -->
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block text-xs text-s1-muted mb-1">Action</label>
              <select v-model="form.action" class="input w-full text-sm">
                <option value="Allow">Allow</option>
                <option value="Block">Block</option>
                <option value="Read-Only">Read-Only</option>
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

          <!-- Interface + Rule Type -->
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block text-xs text-s1-muted mb-1">Interface</label>
              <select v-model="form.interface" class="input w-full text-sm">
                <option value="USB">USB</option>
                <option value="Bluetooth">Bluetooth</option>
                <option value="Thunderbolt">Thunderbolt</option>
                <option value="SDCard">SD Card</option>
              </select>
            </div>
            <div>
              <label class="block text-xs text-s1-muted mb-1">Rule Type</label>
              <select v-model="form.ruleType" class="input w-full text-sm">
                <option value="class">Class</option>
                <option value="vendorId">Vendor ID</option>
                <option value="productId">Product ID</option>
                <option value="deviceId">Device ID</option>
                <option value="uid">UID</option>
              </select>
            </div>
          </div>

          <!-- Device Class -->
          <div>
            <label class="block text-xs text-s1-muted mb-1">Device Class</label>
            <select v-model="form.deviceClass" class="input w-full text-sm">
              <option v-for="dc in DEVICE_CLASSES" :key="dc" :value="dc">{{ dc }}</option>
            </select>
          </div>

          <!-- Access Permission -->
          <div>
            <label class="block text-xs text-s1-muted mb-1">Access Permission</label>
            <select v-model="form.accessPermission" class="input w-full text-sm">
              <option value="Not-Applicable">Not Applicable</option>
              <option value="Read-Only">Read-Only</option>
              <option value="Read-Write">Read-Write</option>
            </select>
          </div>

          <!-- Identifier fields -->
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block text-xs text-s1-muted mb-1">Vendor ID</label>
              <input v-model="form.vendorId" class="input w-full text-sm font-mono" placeholder="e.g. 0x1234" />
            </div>
            <div>
              <label class="block text-xs text-s1-muted mb-1">Product ID</label>
              <input v-model="form.productId" class="input w-full text-sm font-mono" placeholder="e.g. 0x5678" />
            </div>
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block text-xs text-s1-muted mb-1">Device ID</label>
              <input v-model="form.deviceId" class="input w-full text-sm font-mono" placeholder="Optional" />
            </div>
            <div>
              <label class="block text-xs text-s1-muted mb-1">UID</label>
              <input v-model="form.uid" class="input w-full text-sm font-mono" placeholder="Optional" />
            </div>
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
