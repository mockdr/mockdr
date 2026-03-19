<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ensureGraphAuth, graphClient } from '../../api/graph'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

interface UpdateRing {
  id: string
  displayName: string
  description: string | null
  qualityUpdatesDeferralPeriodInDays: number
  featureUpdatesDeferralPeriodInDays: number
}

const loading = ref(false)
const rings = ref<UpdateRing[]>([])

async function fetchRings(): Promise<void> {
  loading.value = true
  try {
    await ensureGraphAuth()
    const res = await graphClient.get('/beta/deviceManagement/windowsUpdateForBusinessConfigurations', {
      params: { $top: 999 },
    }) as { value: UpdateRing[] }
    rings.value = res.value ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchRings())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="font-bold" style="color: #0078D4">Graph</span> Update Rings
        </h1>
        <p class="text-s1-muted text-sm">Windows Update for Business configurations</p>
      </div>
      <button @click="fetchRings()" class="btn-ghost flex items-center gap-2">
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
            <th class="table-header text-left">Quality Deferral (days)</th>
            <th class="table-header text-left">Feature Deferral (days)</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !rings.length" :rows="8" />
          <template v-else>
            <tr v-for="ring in rings" :key="ring.id" class="table-row">
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ ring.displayName }}</div>
              </td>
              <td class="table-cell text-sm text-s1-muted truncate max-w-[300px]">
                {{ ring.description || '—' }}
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ ring.qualityUpdatesDeferralPeriodInDays }}</td>
              <td class="table-cell text-sm text-s1-subtle">{{ ring.featureUpdatesDeferralPeriodInDays }}</td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !rings.length"
        icon="--"
        title="No update rings"
        description="No Windows Update for Business configurations available."
      />
    </div>
  </div>
</template>
