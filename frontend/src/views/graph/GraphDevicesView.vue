<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ensureGraphAuth, graphDevicesApi } from '../../api/graph'
import type { GraphManagedDevice } from '../../types/graph'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const devices = ref<GraphManagedDevice[]>([])

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

async function fetchDevices(): Promise<void> {
  loading.value = true
  try {
    await ensureGraphAuth()
    const res = await graphDevicesApi.list({ $top: 999 })
    devices.value = res.value ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchDevices())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="font-bold" style="color: #0078D4">Graph</span> Managed Devices
        </h1>
        <p class="text-s1-muted text-sm">Intune managed devices</p>
      </div>
      <button @click="fetchDevices()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Device Name</th>
            <th class="table-header text-left">OS</th>
            <th class="table-header text-left">Compliance</th>
            <th class="table-header text-left">Last Sync</th>
            <th class="table-header text-left">Owner (UPN)</th>
            <th class="table-header text-left">Model</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !devices.length" :rows="8" />
          <template v-else>
            <tr v-for="device in devices" :key="device.id" class="table-row">
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ device.deviceName }}</div>
              </td>
              <td class="table-cell text-sm text-s1-subtle">
                {{ device.operatingSystem }} {{ device.osVersion }}
              </td>
              <td class="table-cell">
                <span
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="complianceBadgeClass(device.complianceState)"
                >
                  {{ complianceLabel(device.complianceState) }}
                </span>
              </td>
              <td class="table-cell text-xs text-s1-muted">
                {{ relativeTime(device.lastSyncDateTime) }}
              </td>
              <td class="table-cell">
                <span class="font-mono text-xs text-s1-muted">{{ device.userPrincipalName }}</span>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ device.model }}</td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !devices.length"
        icon="--"
        title="No devices found"
        description="No managed devices available."
      />
    </div>
  </div>
</template>
