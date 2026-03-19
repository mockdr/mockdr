<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { RefreshCw } from 'lucide-vue-next'
import { sentinelIncidentApi } from '../../api/sentinel'
import type { ArmResource, SentinelIncidentProps } from '../../types/sentinel'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const router = useRouter()
const loading = ref(false)
const incidents = ref<ArmResource<SentinelIncidentProps>[]>([])

let timer: ReturnType<typeof setInterval>

const filterStatus = ref('')
const filterSeverity = ref('')

function severityBadgeClass(severity: string): string {
  switch ((severity ?? '').toLowerCase()) {
    case 'high': return 'bg-red-500/15 text-red-400'
    case 'medium': return 'bg-orange-500/15 text-orange-400'
    case 'low': return 'bg-yellow-500/15 text-yellow-400'
    case 'informational': return 'bg-blue-500/15 text-blue-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function statusBadgeClass(status: string): string {
  switch ((status ?? '').toLowerCase()) {
    case 'new': return 'bg-blue-500/15 text-blue-400'
    case 'active': return 'bg-yellow-500/15 text-yellow-400'
    case 'closed': return 'bg-green-500/15 text-green-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

const filteredIncidents = computed(() => {
  let result = incidents.value
  if (filterStatus.value) {
    result = result.filter(i => i.properties.status === filterStatus.value)
  }
  if (filterSeverity.value) {
    result = result.filter(i => i.properties.severity === filterSeverity.value)
  }
  return result
})

async function fetchIncidents(): Promise<void> {
  loading.value = true
  try {
    const res = await sentinelIncidentApi.list()
    incidents.value = res.value ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  fetchIncidents()
  timer = setInterval(fetchIncidents, 30000)
})

onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="text-green-600 font-bold">SNTL</span> Incidents
        </h1>
        <p class="text-s1-muted text-sm">Microsoft Sentinel incident management</p>
      </div>
      <button @click="fetchIncidents()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Filter bar -->
    <div class="card p-4 flex flex-wrap gap-3">
      <select v-model="filterStatus" class="select">
        <option value="">All Statuses</option>
        <option value="New">New</option>
        <option value="Active">Active</option>
        <option value="Closed">Closed</option>
      </select>
      <select v-model="filterSeverity" class="select">
        <option value="">All Severities</option>
        <option value="High">High</option>
        <option value="Medium">Medium</option>
        <option value="Low">Low</option>
        <option value="Informational">Informational</option>
      </select>
      <div class="ml-auto text-xs text-s1-muted self-center">
        {{ filteredIncidents.length }} of {{ incidents.length }} incidents
      </div>
    </div>

    <!-- Table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Title</th>
            <th class="table-header text-left">Severity</th>
            <th class="table-header text-left">Status</th>
            <th class="table-header text-left">Provider</th>
            <th class="table-header text-left">Alerts</th>
            <th class="table-header text-left">Owner</th>
            <th class="table-header text-left">Created</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !incidents.length" :rows="8" />
          <template v-else>
            <tr
              v-for="inc in filteredIncidents" :key="inc.name"
              class="table-row"
              @click="router.push(`/sentinel/incidents/${inc.name}`)"
            >
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm truncate max-w-[250px]">
                  {{ inc.properties.title }}
                </div>
              </td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="severityBadgeClass(inc.properties.severity)">
                  {{ inc.properties.severity }}
                </span>
              </td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="statusBadgeClass(inc.properties.status)">
                  {{ inc.properties.status }}
                </span>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ inc.properties.providerName || '--' }}</td>
              <td class="table-cell text-sm text-s1-subtle">{{ inc.properties.additionalData?.alertsCount ?? 0 }}</td>
              <td class="table-cell text-sm text-s1-subtle truncate max-w-[120px]">
                {{ inc.properties.owner?.assignedTo || '--' }}
              </td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(inc.properties.createdTimeUtc) }}</td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !filteredIncidents.length"
        icon="--"
        title="No incidents found"
        description="No incidents match your current filters."
      />
    </div>
  </div>
</template>
