<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { sentinelThreatIntelApi } from '../../api/sentinel'
import type { ArmResource, SentinelThreatIndicatorProps } from '../../types/sentinel'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const indicators = ref<ArmResource<SentinelThreatIndicatorProps>[]>([])

let timer: ReturnType<typeof setInterval>

function patternTypeBadgeClass(patternType: string): string {
  switch ((patternType ?? '').toLowerCase()) {
    case 'url': return 'bg-purple-500/15 text-purple-400'
    case 'ipv4-addr':
    case 'ipv6-addr': return 'bg-orange-500/15 text-orange-400'
    case 'domain-name': return 'bg-blue-500/15 text-blue-400'
    case 'file': return 'bg-yellow-500/15 text-yellow-400'
    case 'email-addr': return 'bg-cyan-500/15 text-cyan-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function fetchIndicators(): Promise<void> {
  loading.value = true
  try {
    const res = await sentinelThreatIntelApi.list()
    indicators.value = res.value ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  fetchIndicators()
  timer = setInterval(fetchIndicators, 30000)
})

onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="text-green-600 font-bold">SNTL</span> Threat Intelligence
        </h1>
        <p class="text-s1-muted text-sm">Microsoft Sentinel threat intelligence indicators</p>
      </div>
      <button @click="fetchIndicators()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Display Name</th>
            <th class="table-header text-left">Pattern Type</th>
            <th class="table-header text-left">Source</th>
            <th class="table-header text-left">Confidence</th>
            <th class="table-header text-left">Labels</th>
            <th class="table-header text-left">Valid From</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !indicators.length" :rows="8" />
          <template v-else>
            <tr
              v-for="ind in indicators" :key="ind.name"
              class="table-row"
            >
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm truncate max-w-[200px]">
                  {{ ind.properties.displayName }}
                </div>
                <div class="text-xs text-s1-muted truncate max-w-[200px]">
                  {{ ind.properties.pattern }}
                </div>
              </td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="patternTypeBadgeClass(ind.properties.patternType)">
                  {{ ind.properties.patternType }}
                </span>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ ind.properties.source || '--' }}</td>
              <td class="table-cell">
                <div class="flex items-center gap-2">
                  <div class="w-16 h-1.5 bg-s1-border rounded-full overflow-hidden">
                    <div
                      class="h-full rounded-full"
                      :class="ind.properties.confidence >= 75 ? 'bg-green-500' : ind.properties.confidence >= 50 ? 'bg-yellow-500' : 'bg-red-500'"
                      :style="{ width: `${ind.properties.confidence}%` }"
                    ></div>
                  </div>
                  <span class="text-xs text-s1-text font-mono">{{ ind.properties.confidence }}%</span>
                </div>
              </td>
              <td class="table-cell">
                <div class="flex flex-wrap gap-1">
                  <span v-for="label in (ind.properties.labels ?? []).slice(0, 3)" :key="label"
                    class="text-xs px-1.5 py-0.5 rounded bg-s1-hover text-s1-subtle">
                    {{ label }}
                  </span>
                  <span v-if="(ind.properties.labels ?? []).length > 3"
                    class="text-xs text-s1-muted">
                    +{{ ind.properties.labels.length - 3 }}
                  </span>
                </div>
              </td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(ind.properties.validFrom) }}</td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !indicators.length"
        icon="--"
        title="No threat indicators found"
        description="No threat intelligence indicators are available."
      />
    </div>
  </div>
</template>
