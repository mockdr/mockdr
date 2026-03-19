<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ensureGraphAuth, graphIdentityApi, graphClient } from '../../api/graph'
import type { GraphRiskyUser } from '../../types/graph'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

interface RiskDetection {
  id: string
  userPrincipalName: string
  userDisplayName: string
  riskLevel: string
  riskEventType: string
  detectedDateTime: string
  ipAddress: string
  location?: { city: string | null; countryOrRegion: string | null }
}

const loading = ref(false)
const riskyUsers = ref<GraphRiskyUser[]>([])
const riskDetections = ref<RiskDetection[]>([])

function riskBadgeClass(level: string): string {
  switch (level) {
    case 'high': return 'bg-red-500/15 text-red-400'
    case 'medium': return 'bg-yellow-500/15 text-yellow-400'
    case 'low': return 'bg-blue-500/15 text-blue-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function fetchData(): Promise<void> {
  loading.value = true
  try {
    await ensureGraphAuth()
    const [usersRes, detectionsRes] = await Promise.all([
      graphIdentityApi.listRiskyUsers({ $top: 999 }),
      graphClient.get('/v1.0/identityProtection/riskDetections', { params: { $top: 999 } }) as Promise<{ value: RiskDetection[] }>,
    ])
    riskyUsers.value = usersRes.value ?? []
    riskDetections.value = detectionsRes.value ?? []
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
          <span class="font-bold" style="color: #0078D4">Graph</span> Identity Protection
        </h1>
        <p class="text-s1-muted text-sm">Risky users and risk detections</p>
      </div>
      <button @click="fetchData()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Risky Users Table -->
    <div class="card overflow-hidden">
      <div class="px-4 py-3 border-b border-s1-border">
        <h2 class="text-sm font-semibold text-s1-text">Risky Users</h2>
      </div>
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">User</th>
            <th class="table-header text-left">UPN</th>
            <th class="table-header text-left">Risk Level</th>
            <th class="table-header text-left">Risk State</th>
            <th class="table-header text-left">Last Updated</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !riskyUsers.length" :rows="5" />
          <template v-else>
            <tr v-for="user in riskyUsers" :key="user.id" class="table-row">
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ user.userDisplayName }}</div>
              </td>
              <td class="table-cell">
                <span class="font-mono text-xs text-s1-muted">{{ user.userPrincipalName }}</span>
              </td>
              <td class="table-cell">
                <span
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="riskBadgeClass(user.riskLevel)"
                >
                  {{ user.riskLevel }}
                </span>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ user.riskState }}</td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(user.riskLastUpdatedDateTime) }}</td>
            </tr>
          </template>
        </tbody>
      </table>
      <EmptyState
        v-if="!loading && !riskyUsers.length"
        icon="--"
        title="No risky users"
        description="No risky users detected."
      />
    </div>

    <!-- Risk Detections Table -->
    <div class="card overflow-hidden">
      <div class="px-4 py-3 border-b border-s1-border">
        <h2 class="text-sm font-semibold text-s1-text">Risk Detections</h2>
      </div>
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">User</th>
            <th class="table-header text-left">Risk Type</th>
            <th class="table-header text-left">Risk Level</th>
            <th class="table-header text-left">IP Address</th>
            <th class="table-header text-left">Detected</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !riskDetections.length" :rows="5" />
          <template v-else>
            <tr v-for="det in riskDetections" :key="det.id" class="table-row">
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ det.userDisplayName }}</div>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ det.riskEventType }}</td>
              <td class="table-cell">
                <span
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="riskBadgeClass(det.riskLevel)"
                >
                  {{ det.riskLevel }}
                </span>
              </td>
              <td class="table-cell">
                <span class="font-mono text-xs text-s1-muted">{{ det.ipAddress }}</span>
              </td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(det.detectedDateTime) }}</td>
            </tr>
          </template>
        </tbody>
      </table>
      <EmptyState
        v-if="!loading && !riskDetections.length"
        icon="--"
        title="No risk detections"
        description="No risk detections found."
      />
    </div>
  </div>
</template>
