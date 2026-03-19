<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ensureGraphAuth, graphIntuneApi, graphClient } from '../../api/graph'
import type { GraphMobileApp } from '../../types/graph'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

interface AppProtectionPolicy {
  id: string
  displayName: string
  description: string | null
  version: string
}

const loading = ref(false)
const apps = ref<GraphMobileApp[]>([])
const appPolicies = ref<AppProtectionPolicy[]>([])

function publishingBadgeClass(state: string): string {
  switch (state) {
    case 'published': return 'bg-green-500/15 text-green-400'
    case 'processing': return 'bg-yellow-500/15 text-yellow-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function fetchData(): Promise<void> {
  loading.value = true
  try {
    await ensureGraphAuth()
    const [appsRes, policiesRes] = await Promise.all([
      graphIntuneApi.listApps({ $top: 999 }),
      graphClient.get('/v1.0/deviceAppManagement/managedAppPolicies', { params: { $top: 999 } }) as Promise<{ value: AppProtectionPolicy[] }>,
    ])
    apps.value = appsRes.value ?? []
    appPolicies.value = policiesRes.value ?? []
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
          <span class="font-bold" style="color: #0078D4">Graph</span> Apps
        </h1>
        <p class="text-s1-muted text-sm">Intune mobile apps and app protection policies</p>
      </div>
      <button @click="fetchData()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Mobile Apps Table -->
    <div class="card overflow-hidden">
      <div class="px-4 py-3 border-b border-s1-border">
        <h2 class="text-sm font-semibold text-s1-text">Mobile Apps</h2>
      </div>
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Name</th>
            <th class="table-header text-left">Publisher</th>
            <th class="table-header text-left">State</th>
            <th class="table-header text-left">Installed</th>
            <th class="table-header text-left">Failed</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !apps.length" :rows="5" />
          <template v-else>
            <tr v-for="app in apps" :key="app.id" class="table-row">
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ app.displayName }}</div>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ app.publisher }}</td>
              <td class="table-cell">
                <span
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="publishingBadgeClass(app.publishingState)"
                >
                  {{ app.publishingState }}
                </span>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ app.installSummary?.installedDeviceCount ?? '—' }}</td>
              <td class="table-cell text-sm text-s1-subtle">{{ app.installSummary?.failedDeviceCount ?? '—' }}</td>
            </tr>
          </template>
        </tbody>
      </table>
      <EmptyState
        v-if="!loading && !apps.length"
        icon="--"
        title="No mobile apps"
        description="No mobile apps found."
      />
    </div>

    <!-- App Protection Policies Table -->
    <div class="card overflow-hidden">
      <div class="px-4 py-3 border-b border-s1-border">
        <h2 class="text-sm font-semibold text-s1-text">App Protection Policies</h2>
      </div>
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Name</th>
            <th class="table-header text-left">Description</th>
            <th class="table-header text-left">Version</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !appPolicies.length" :rows="3" />
          <template v-else>
            <tr v-for="policy in appPolicies" :key="policy.id" class="table-row">
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ policy.displayName }}</div>
              </td>
              <td class="table-cell text-sm text-s1-muted truncate max-w-[300px]">
                {{ policy.description || '—' }}
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ policy.version }}</td>
            </tr>
          </template>
        </tbody>
      </table>
      <EmptyState
        v-if="!loading && !appPolicies.length"
        icon="--"
        title="No protection policies"
        description="No app protection policies found."
      />
    </div>
  </div>
</template>
