<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw, Play } from 'lucide-vue-next'
import { xdrScriptsApi } from '../../api/cortex'
import type { XdrScript } from '../../types/cortex'
import { formatEpoch } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const scripts = ref<XdrScript[]>([])
const totalCount = ref(0)

function riskBadgeClass(isHighRisk: boolean): string {
  return isHighRisk
    ? 'bg-red-500/15 text-red-400'
    : 'bg-green-500/15 text-green-400'
}

function typeBadgeClass(scriptType: string): string {
  switch (scriptType) {
    case 'python': return 'bg-blue-500/15 text-blue-400'
    case 'powershell': return 'bg-purple-500/15 text-purple-400'
    case 'shell': return 'bg-yellow-500/15 text-yellow-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function fetchScripts(): Promise<void> {
  loading.value = true
  try {
    const res = await xdrScriptsApi.list()
    scripts.value = res.reply?.scripts ?? []
    totalCount.value = res.reply?.total_count ?? scripts.value.length
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchScripts())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="text-orange-500 font-bold">XDR</span> Scripts
        </h1>
        <p class="text-s1-muted text-sm">Response scripts for endpoint investigation and remediation</p>
      </div>
      <button @click="fetchScripts()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Summary cards -->
    <div class="grid grid-cols-3 gap-3">
      <div class="card p-4">
        <div class="text-xs text-s1-muted uppercase tracking-wider">Total Scripts</div>
        <div class="text-2xl font-bold text-s1-text mt-1">{{ totalCount }}</div>
      </div>
      <div class="card p-4">
        <div class="text-xs text-s1-muted uppercase tracking-wider">High Risk</div>
        <div class="text-2xl font-bold text-red-400 mt-1">
          {{ scripts.filter(s => s.is_high_risk).length }}
        </div>
      </div>
      <div class="card p-4">
        <div class="text-xs text-s1-muted uppercase tracking-wider">Safe</div>
        <div class="text-2xl font-bold text-green-400 mt-1">
          {{ scripts.filter(s => !s.is_high_risk).length }}
        </div>
      </div>
    </div>

    <!-- Table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Name</th>
            <th class="table-header text-left">Description</th>
            <th class="table-header text-left">Type</th>
            <th class="table-header text-left">Risk Level</th>
            <th class="table-header text-left">Modified</th>
            <th class="table-header text-right w-20">Run</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !scripts.length" :rows="8" />
          <template v-else>
            <tr v-for="script in scripts" :key="script.script_id" class="table-row">
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ script.name }}</div>
                <div class="text-xs text-s1-muted font-mono">{{ script.script_id }}</div>
              </td>
              <td class="table-cell text-sm text-s1-subtle max-w-[300px] truncate">
                {{ script.description }}
              </td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="typeBadgeClass(script.script_type)">
                  {{ script.script_type }}
                </span>
              </td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="riskBadgeClass(script.is_high_risk)">
                  {{ script.is_high_risk ? 'High Risk' : 'Safe' }}
                </span>
              </td>
              <td class="table-cell text-xs text-s1-muted">
                {{ formatEpoch(script.modification_date) }}
              </td>
              <td class="table-cell text-right">
                <button
                  class="p-1.5 rounded hover:bg-orange-500/10 text-s1-muted hover:text-orange-400 transition-colors"
                  title="Execute script"
                >
                  <Play class="w-3.5 h-3.5" />
                </button>
              </td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !scripts.length"
        icon="--"
        title="No scripts"
        description="No response scripts available."
      />
    </div>
  </div>
</template>
