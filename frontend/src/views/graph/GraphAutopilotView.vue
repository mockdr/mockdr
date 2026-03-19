<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ensureGraphAuth, graphIntuneApi, graphClient } from '../../api/graph'
import type { GraphAutopilotDevice } from '../../types/graph'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

interface AutopilotProfile {
  id: string
  displayName: string
  description: string | null
  lastModifiedDateTime: string
}

const loading = ref(false)
const devices = ref<GraphAutopilotDevice[]>([])
const profiles = ref<AutopilotProfile[]>([])

function enrollmentBadgeClass(state: string): string {
  switch (state) {
    case 'enrolled': return 'bg-green-500/15 text-green-400'
    case 'pendingReset': return 'bg-yellow-500/15 text-yellow-400'
    case 'notContacted': return 'bg-gray-500/15 text-gray-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function fetchData(): Promise<void> {
  loading.value = true
  try {
    await ensureGraphAuth()
    const [devicesRes, profilesRes] = await Promise.all([
      graphIntuneApi.listAutopilot({ $top: 999 }),
      graphClient.get('/v1.0/deviceManagement/windowsAutopilotDeploymentProfiles', { params: { $top: 999 } }) as Promise<{ value: AutopilotProfile[] }>,
    ])
    devices.value = devicesRes.value ?? []
    profiles.value = profilesRes.value ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchData())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="font-bold" style="color: #0078D4">Graph</span> Autopilot
        </h1>
        <p class="text-s1-muted text-sm">Windows Autopilot devices and deployment profiles</p>
      </div>
      <button @click="fetchData()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Devices Table -->
    <div class="card overflow-hidden">
      <div class="px-4 py-3 border-b border-s1-border">
        <h2 class="text-sm font-semibold text-s1-text">Autopilot Devices</h2>
      </div>
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Serial Number</th>
            <th class="table-header text-left">Model</th>
            <th class="table-header text-left">Manufacturer</th>
            <th class="table-header text-left">Group Tag</th>
            <th class="table-header text-left">Enrollment State</th>
            <th class="table-header text-left">Last Contact</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !devices.length" :rows="5" />
          <template v-else>
            <tr v-for="device in devices" :key="device.id" class="table-row">
              <td class="table-cell">
                <span class="font-mono text-xs text-s1-text">{{ device.serialNumber }}</span>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ device.model }}</td>
              <td class="table-cell text-sm text-s1-subtle">{{ device.manufacturer }}</td>
              <td class="table-cell text-sm text-s1-muted">{{ device.groupTag ?? '—' }}</td>
              <td class="table-cell">
                <span
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="enrollmentBadgeClass(device.enrollmentState)"
                >
                  {{ device.enrollmentState }}
                </span>
              </td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(device.lastContactedDateTime) }}</td>
            </tr>
          </template>
        </tbody>
      </table>
      <EmptyState
        v-if="!loading && !devices.length"
        icon="--"
        title="No Autopilot devices"
        description="No Windows Autopilot devices found."
      />
    </div>

    <!-- Profiles Table -->
    <div class="card overflow-hidden">
      <div class="px-4 py-3 border-b border-s1-border">
        <h2 class="text-sm font-semibold text-s1-text">Deployment Profiles</h2>
      </div>
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Name</th>
            <th class="table-header text-left">Description</th>
            <th class="table-header text-left">Last Modified</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !profiles.length" :rows="3" />
          <template v-else>
            <tr v-for="profile in profiles" :key="profile.id" class="table-row">
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ profile.displayName }}</div>
              </td>
              <td class="table-cell text-sm text-s1-muted truncate max-w-[300px]">
                {{ profile.description || '—' }}
              </td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(profile.lastModifiedDateTime) }}</td>
            </tr>
          </template>
        </tbody>
      </table>
      <EmptyState
        v-if="!loading && !profiles.length"
        icon="--"
        title="No deployment profiles"
        description="No Autopilot deployment profiles found."
      />
    </div>
  </div>
</template>
