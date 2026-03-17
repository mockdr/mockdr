<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw, Plus, Trash2 } from 'lucide-vue-next'
import { ensureMdeAuth, mdeIndicatorsApi } from '../../api/defender'
import type { MdeIndicator } from '../../types/defender'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const indicators = ref<MdeIndicator[]>([])
const showCreateDialog = ref(false)

// Create form
const newIndicator = ref({
  indicatorValue: '',
  indicatorType: 'IpAddress',
  action: 'AlertAndBlock',
  severity: 'High',
  title: '',
  description: '',
})

function severityBadgeClass(severity: string): string {
  switch (severity) {
    case 'High': return 'bg-red-500/15 text-red-400'
    case 'Medium': return 'bg-orange-500/15 text-orange-400'
    case 'Low': return 'bg-yellow-500/15 text-yellow-400'
    case 'Informational': return 'bg-gray-500/15 text-gray-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function actionBadgeClass(action: string): string {
  switch (action) {
    case 'AlertAndBlock': return 'bg-red-500/15 text-red-400'
    case 'Alert': return 'bg-yellow-500/15 text-yellow-400'
    case 'Allowed': return 'bg-green-500/15 text-green-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function fetchIndicators(): Promise<void> {
  loading.value = true
  try {
    await ensureMdeAuth()
    const res = await mdeIndicatorsApi.list({ $top: 100 })
    indicators.value = res.value ?? []
  } finally {
    loading.value = false
  }
}

async function createIndicator(): Promise<void> {
  loading.value = true
  try {
    await mdeIndicatorsApi.create(newIndicator.value)
    showCreateDialog.value = false
    newIndicator.value = {
      indicatorValue: '',
      indicatorType: 'IpAddress',
      action: 'AlertAndBlock',
      severity: 'High',
      title: '',
      description: '',
    }
    await fetchIndicators()
  } finally {
    loading.value = false
  }
}

async function deleteIndicator(id: string): Promise<void> {
  loading.value = true
  try {
    await mdeIndicatorsApi.delete(id)
    await fetchIndicators()
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchIndicators())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="text-green-500 font-bold">MDE</span> Indicators
        </h1>
        <p class="text-s1-muted text-sm">Custom indicators of compromise</p>
      </div>
      <div class="flex items-center gap-2">
        <button @click="showCreateDialog = true" class="btn-ghost flex items-center gap-2 text-green-400">
          <Plus class="w-3.5 h-3.5" /> Create
        </button>
        <button @click="fetchIndicators()" class="btn-ghost flex items-center gap-2">
          <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
          Refresh
        </button>
      </div>
    </div>

    <!-- Create dialog -->
    <div v-if="showCreateDialog" class="card p-5 border-green-500/40 space-y-4">
      <h3 class="text-sm font-semibold text-s1-text">Create Indicator</h3>
      <div class="grid grid-cols-2 gap-4">
        <div>
          <label class="text-xs text-s1-muted">Value</label>
          <input v-model="newIndicator.indicatorValue" class="input mt-1" placeholder="e.g. 192.168.1.1" />
        </div>
        <div>
          <label class="text-xs text-s1-muted">Type</label>
          <select v-model="newIndicator.indicatorType" class="select mt-1">
            <option value="IpAddress">IP Address</option>
            <option value="DomainName">Domain Name</option>
            <option value="Url">URL</option>
            <option value="FileSha1">File SHA1</option>
            <option value="FileSha256">File SHA256</option>
            <option value="CertificateThumbprint">Certificate</option>
          </select>
        </div>
        <div>
          <label class="text-xs text-s1-muted">Action</label>
          <select v-model="newIndicator.action" class="select mt-1">
            <option value="AlertAndBlock">Alert and Block</option>
            <option value="Alert">Alert Only</option>
            <option value="Allowed">Allowed</option>
          </select>
        </div>
        <div>
          <label class="text-xs text-s1-muted">Severity</label>
          <select v-model="newIndicator.severity" class="select mt-1">
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Informational">Informational</option>
          </select>
        </div>
        <div>
          <label class="text-xs text-s1-muted">Title</label>
          <input v-model="newIndicator.title" class="input mt-1" placeholder="Indicator title" />
        </div>
        <div>
          <label class="text-xs text-s1-muted">Description</label>
          <input v-model="newIndicator.description" class="input mt-1" placeholder="Optional description" />
        </div>
      </div>
      <div class="flex items-center gap-2">
        <button @click="createIndicator()" :disabled="!newIndicator.indicatorValue || !newIndicator.title || loading"
          class="btn-ghost text-green-400 text-sm">
          Create
        </button>
        <button @click="showCreateDialog = false" class="btn-ghost text-sm">Cancel</button>
      </div>
    </div>

    <!-- Table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Value</th>
            <th class="table-header text-left">Type</th>
            <th class="table-header text-left">Action</th>
            <th class="table-header text-left">Severity</th>
            <th class="table-header text-left">Title</th>
            <th class="table-header w-10"></th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !indicators.length" :rows="8" />
          <template v-else>
            <tr v-for="ind in indicators" :key="ind.indicatorId" class="table-row">
              <td class="table-cell">
                <span class="font-mono text-xs text-s1-text">{{ ind.indicatorValue }}</span>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ ind.indicatorType }}</td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="actionBadgeClass(ind.action)">
                  {{ ind.action }}
                </span>
              </td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="severityBadgeClass(ind.severity)">
                  {{ ind.severity }}
                </span>
              </td>
              <td class="table-cell text-sm text-s1-subtle truncate max-w-[200px]">{{ ind.title }}</td>
              <td class="table-cell" @click.stop>
                <button @click="deleteIndicator(ind.indicatorId)" class="btn-ghost text-red-400 p-1">
                  <Trash2 class="w-3.5 h-3.5" />
                </button>
              </td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !indicators.length"
        icon="--"
        title="No indicators"
        description="Create custom indicators to protect your environment."
      />
    </div>
  </div>
</template>
