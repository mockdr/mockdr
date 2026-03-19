<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { RefreshCw, Trash2, LogOut, RefreshCcw, Search } from 'lucide-vue-next'
import { ensureGraphAuth, graphDevicesApi } from '../../api/graph'
import type { GraphManagedDevice } from '../../types/graph'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

const route = useRoute()
const loading = ref(false)
const device = ref<GraphManagedDevice | null>(null)
const toast = ref('')

function complianceBadgeClass(state: string): string {
  switch (state) {
    case 'compliant': return 'bg-green-500/15 text-green-400'
    case 'noncompliant': return 'bg-red-500/15 text-red-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function complianceLabel(state: string): string {
  switch (state) {
    case 'compliant': return 'Compliant'
    case 'noncompliant': return 'Noncompliant'
    default: return 'Unknown'
  }
}

function showToast(msg: string): void {
  toast.value = msg
  setTimeout(() => { toast.value = '' }, 3000)
}

async function fetchDevice(): Promise<void> {
  loading.value = true
  try {
    await ensureGraphAuth()
    device.value = await graphDevicesApi.get(route.params.id as string)
  } finally {
    loading.value = false
  }
}

async function wipeDevice(): Promise<void> {
  try {
    await ensureGraphAuth()
    await graphDevicesApi.wipe(route.params.id as string)
    showToast('Wipe command sent successfully')
  } catch { showToast('Failed to send wipe command') }
}

async function retireDevice(): Promise<void> {
  try {
    await ensureGraphAuth()
    // retire uses the same pattern as wipe
    const { graphClient } = await import('../../api/graph')
    await graphClient.post(`/v1.0/deviceManagement/managedDevices/${route.params.id}/retire`)
    showToast('Retire command sent successfully')
  } catch { showToast('Failed to send retire command') }
}

async function syncDevice(): Promise<void> {
  try {
    await ensureGraphAuth()
    await graphDevicesApi.sync(route.params.id as string)
    showToast('Sync command sent successfully')
  } catch { showToast('Failed to send sync command') }
}

async function scanDevice(): Promise<void> {
  try {
    await ensureGraphAuth()
    await graphDevicesApi.scan(route.params.id as string)
    showToast('Scan command sent successfully')
  } catch { showToast('Failed to send scan command') }
}

onMounted(() => fetchDevice())
</script>

<template>
  <div class="space-y-4">
    <!-- Toast -->
    <div v-if="toast" class="fixed top-4 right-4 z-50 card p-3 bg-green-500/10 border-green-500/40 text-green-400 text-sm">
      {{ toast }}
    </div>

    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="font-bold" style="color: #0078D4">Graph</span> Device Detail
        </h1>
        <p class="text-s1-muted text-sm">{{ device?.deviceName ?? 'Loading...' }}</p>
      </div>
      <button @click="fetchDevice()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <LoadingSkeleton v-if="loading && !device" :rows="6" />

    <template v-if="device">
      <!-- Action Buttons -->
      <div class="flex gap-2">
        <button @click="wipeDevice()" class="btn-ghost flex items-center gap-2 text-red-400 hover:bg-red-500/10">
          <Trash2 class="w-3.5 h-3.5" /> Wipe
        </button>
        <button @click="retireDevice()" class="btn-ghost flex items-center gap-2 text-yellow-400 hover:bg-yellow-500/10">
          <LogOut class="w-3.5 h-3.5" /> Retire
        </button>
        <button @click="syncDevice()" class="btn-ghost flex items-center gap-2">
          <RefreshCcw class="w-3.5 h-3.5" /> Sync
        </button>
        <button @click="scanDevice()" class="btn-ghost flex items-center gap-2">
          <Search class="w-3.5 h-3.5" /> Scan
        </button>
      </div>

      <!-- Device Info Card -->
      <div class="card p-5 space-y-3">
        <h2 class="text-sm font-semibold text-s1-text">Device Information</h2>
        <div class="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span class="text-s1-muted">Device Name</span>
            <div class="text-s1-text font-medium">{{ device.deviceName }}</div>
          </div>
          <div>
            <span class="text-s1-muted">Operating System</span>
            <div class="text-s1-text">{{ device.operatingSystem }}</div>
          </div>
          <div>
            <span class="text-s1-muted">OS Version</span>
            <div class="text-s1-text font-mono text-xs">{{ device.osVersion }}</div>
          </div>
          <div>
            <span class="text-s1-muted">Compliance State</span>
            <div>
              <span
                class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                :class="complianceBadgeClass(device.complianceState)"
              >
                {{ complianceLabel(device.complianceState) }}
              </span>
            </div>
          </div>
          <div>
            <span class="text-s1-muted">Last Sync</span>
            <div class="text-s1-text text-xs">{{ relativeTime(device.lastSyncDateTime) }}</div>
          </div>
          <div>
            <span class="text-s1-muted">Model</span>
            <div class="text-s1-text">{{ device.model }}</div>
          </div>
          <div>
            <span class="text-s1-muted">Manufacturer</span>
            <div class="text-s1-text">{{ device.manufacturer }}</div>
          </div>
          <div>
            <span class="text-s1-muted">Owner (UPN)</span>
            <div class="text-s1-text font-mono text-xs">{{ device.userPrincipalName }}</div>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>
