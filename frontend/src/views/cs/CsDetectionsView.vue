<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { RefreshCw } from 'lucide-vue-next'
import { ensureCsAuth, csDetectionsApi } from '../../api/crowdstrike'
import { relativeTime } from '../../utils/formatters'
import type { CsDetection } from '../../types/crowdstrike'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const router = useRouter()
const loading = ref(false)
const detections = ref<CsDetection[]>([])
const total = ref(0)
const offset = ref(0)
const limit = 25

// Filters
const filterSeverity = ref('')
const filterStatus = ref('')

function severityBadgeClass(severity: number): string {
  if (severity >= 80) return 'bg-red-500/15 text-red-400'
  if (severity >= 60) return 'bg-orange-500/15 text-orange-400'
  if (severity >= 40) return 'bg-yellow-500/15 text-yellow-400'
  if (severity >= 20) return 'bg-blue-500/15 text-blue-400'
  return 'bg-gray-500/15 text-gray-400'
}

function statusBadgeClass(status: string): string {
  switch (status) {
    case 'new': return 'bg-blue-500/15 text-blue-400'
    case 'in_progress': return 'bg-yellow-500/15 text-yellow-400'
    case 'true_positive': return 'bg-red-500/15 text-red-400'
    case 'false_positive': return 'bg-green-500/15 text-green-400'
    case 'closed': return 'bg-gray-500/15 text-gray-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function fetchDetections(append = false): Promise<void> {
  loading.value = true
  try {
    await ensureCsAuth()

    const params: Record<string, unknown> = {
      offset: append ? offset.value : 0,
      limit,
    }

    const filters: string[] = []
    if (filterSeverity.value) filters.push(`max_severity_displayname:'${filterSeverity.value}'`)
    if (filterStatus.value) filters.push(`status:'${filterStatus.value}'`)
    if (filters.length) params['filter'] = filters.join('+')

    const idsRes = await csDetectionsApi.queryIds(params)
    total.value = idsRes.meta.pagination?.total ?? idsRes.resources.length

    if (idsRes.resources.length === 0) {
      if (!append) detections.value = []
      return
    }

    const entitiesRes = await csDetectionsApi.getEntities(idsRes.resources)

    if (append) {
      detections.value = [...detections.value, ...entitiesRes.resources]
    } else {
      detections.value = entitiesRes.resources
      offset.value = 0
    }
    offset.value += idsRes.resources.length
  } finally {
    loading.value = false
  }
}

const hasMore = computed(() => offset.value < total.value)

watch([filterSeverity, filterStatus], () => fetchDetections())

onMounted(() => fetchDetections())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="text-red-500 font-bold">CS</span> Detections
        </h1>
        <p class="text-s1-muted text-sm">{{ total }} detections total</p>
      </div>
      <button @click="fetchDetections()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Filter bar -->
    <div class="card p-4 flex flex-wrap gap-3">
      <select v-model="filterSeverity" class="select">
        <option value="">All Severities</option>
        <option value="Critical">Critical</option>
        <option value="High">High</option>
        <option value="Medium">Medium</option>
        <option value="Low">Low</option>
        <option value="Informational">Informational</option>
      </select>
      <select v-model="filterStatus" class="select">
        <option value="">All Statuses</option>
        <option value="new">New</option>
        <option value="in_progress">In Progress</option>
        <option value="true_positive">True Positive</option>
        <option value="false_positive">False Positive</option>
        <option value="closed">Closed</option>
      </select>
    </div>

    <!-- Table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Hostname</th>
            <th class="table-header text-left">Severity</th>
            <th class="table-header text-left">Status</th>
            <th class="table-header text-left">Scenario</th>
            <th class="table-header text-left">Tactic</th>
            <th class="table-header text-left">Created</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !detections.length" :rows="8" />
          <template v-else>
            <tr
              v-for="det in detections" :key="det.composite_id"
              class="table-row"
              @click="router.push(`/crowdstrike/detections/${encodeURIComponent(det.composite_id)}`)"
            >
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ det.device?.hostname ?? 'Unknown' }}</div>
                <div class="text-xs text-s1-muted">{{ det.device?.platform_name }} | {{ det.device?.external_ip }}</div>
              </td>
              <td class="table-cell">
                <span
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="severityBadgeClass(det.max_severity)"
                >
                  {{ det.max_severity_displayname }}
                </span>
              </td>
              <td class="table-cell">
                <span
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="statusBadgeClass(det.status)"
                >
                  {{ det.status }}
                </span>
              </td>
              <td class="table-cell text-sm text-s1-subtle">
                {{ det.behaviors?.[0]?.scenario ?? '--' }}
              </td>
              <td class="table-cell">
                <div class="text-sm text-s1-subtle">{{ det.behaviors?.[0]?.tactic ?? '--' }}</div>
                <div class="text-xs text-s1-muted">{{ det.behaviors?.[0]?.technique ?? '' }}</div>
              </td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(det.created_timestamp) }}</td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !detections.length"
        icon="--"
        title="No detections found"
        description="No detections match your current filters."
      />

      <div v-if="hasMore" class="p-4 text-center border-t border-s1-border">
        <button @click="fetchDetections(true)" class="btn-ghost text-sm" :disabled="loading">
          Load more detections
        </button>
      </div>
    </div>
  </div>
</template>
