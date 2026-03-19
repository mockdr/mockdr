<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ensureGraphAuth, graphIntuneApi } from '../../api/graph'
import type { GraphCompliancePolicy } from '../../types/graph'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const policies = ref<GraphCompliancePolicy[]>([])

async function fetchPolicies(): Promise<void> {
  loading.value = true
  try {
    await ensureGraphAuth()
    const res = await graphIntuneApi.listCompliance({ $top: 999 })
    policies.value = res.value ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchPolicies())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="font-bold" style="color: #0078D4">Graph</span> Compliance Policies
        </h1>
        <p class="text-s1-muted text-sm">Intune device compliance policies</p>
      </div>
      <button @click="fetchPolicies()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Name</th>
            <th class="table-header text-left">Description</th>
            <th class="table-header text-left">Last Modified</th>
            <th class="table-header text-left">Created</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !policies.length" :rows="8" />
          <template v-else>
            <tr v-for="policy in policies" :key="policy.id" class="table-row">
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ policy.displayName }}</div>
              </td>
              <td class="table-cell text-sm text-s1-muted truncate max-w-[300px]">
                {{ policy.description || '—' }}
              </td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(policy.lastModifiedDateTime) }}</td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(policy.createdDateTime) }}</td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !policies.length"
        icon="--"
        title="No compliance policies"
        description="No device compliance policies available."
      />
    </div>
  </div>
</template>
