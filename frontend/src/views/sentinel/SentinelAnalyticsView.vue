<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { sentinelAlertRuleApi } from '../../api/sentinel'
import type { ArmResource, SentinelAlertRuleProps } from '../../types/sentinel'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const rules = ref<ArmResource<SentinelAlertRuleProps>[]>([])

let timer: ReturnType<typeof setInterval>

function severityBadgeClass(severity: string): string {
  switch ((severity ?? '').toLowerCase()) {
    case 'high': return 'bg-red-500/15 text-red-400'
    case 'medium': return 'bg-orange-500/15 text-orange-400'
    case 'low': return 'bg-yellow-500/15 text-yellow-400'
    case 'informational': return 'bg-blue-500/15 text-blue-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function kindBadgeClass(kind: string): string {
  switch ((kind ?? '').toLowerCase()) {
    case 'scheduled': return 'bg-blue-500/15 text-blue-400'
    case 'fusion': return 'bg-purple-500/15 text-purple-400'
    case 'microsoftsecurityincidentcreation': return 'bg-green-500/15 text-green-400'
    case 'nrt': return 'bg-orange-500/15 text-orange-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function kindLabel(kind: string): string {
  switch ((kind ?? '').toLowerCase()) {
    case 'scheduled': return 'Scheduled'
    case 'fusion': return 'Fusion'
    case 'microsoftsecurityincidentcreation': return 'MS Security'
    case 'nrt': return 'NRT'
    default: return kind || '--'
  }
}

async function fetchRules(): Promise<void> {
  loading.value = true
  try {
    const res = await sentinelAlertRuleApi.list()
    rules.value = res.value ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  fetchRules()
  timer = setInterval(fetchRules, 30000)
})

onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="text-green-600 font-bold">SNTL</span> Analytics Rules
        </h1>
        <p class="text-s1-muted text-sm">Microsoft Sentinel analytics rule configuration</p>
      </div>
      <button @click="fetchRules()" class="btn-ghost flex items-center gap-2">
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
            <th class="table-header text-left">Kind</th>
            <th class="table-header text-left">Severity</th>
            <th class="table-header text-left">Enabled</th>
            <th class="table-header text-left">Tactics</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !rules.length" :rows="8" />
          <template v-else>
            <tr
              v-for="rule in rules" :key="rule.name"
              class="table-row"
            >
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm truncate max-w-[250px]">
                  {{ rule.properties.displayName }}
                </div>
                <div class="text-xs text-s1-muted truncate max-w-[250px]">
                  {{ rule.properties.description }}
                </div>
              </td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="kindBadgeClass(rule.properties.kind ?? '')">
                  {{ kindLabel(rule.properties.kind ?? '') }}
                </span>
              </td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="severityBadgeClass(rule.properties.severity)">
                  {{ rule.properties.severity }}
                </span>
              </td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="rule.properties.enabled ? 'bg-green-500/15 text-green-400' : 'bg-red-500/15 text-red-400'">
                  {{ rule.properties.enabled ? 'Enabled' : 'Disabled' }}
                </span>
              </td>
              <td class="table-cell">
                <div class="flex flex-wrap gap-1">
                  <span v-for="tactic in (rule.properties.tactics ?? []).slice(0, 3)" :key="tactic"
                    class="text-xs px-1.5 py-0.5 rounded bg-s1-hover text-s1-subtle">
                    {{ tactic }}
                  </span>
                  <span v-if="(rule.properties.tactics ?? []).length > 3"
                    class="text-xs text-s1-muted">
                    +{{ rule.properties.tactics.length - 3 }}
                  </span>
                </div>
              </td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !rules.length"
        icon="--"
        title="No analytics rules found"
        description="No analytics rules are currently configured."
      />
    </div>
  </div>
</template>
