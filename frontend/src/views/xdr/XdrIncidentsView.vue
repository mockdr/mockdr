<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { RefreshCw } from 'lucide-vue-next'
import { xdrIncidentsApi } from '../../api/cortex'
import type { XdrIncident } from '../../types/cortex'
import { formatEpoch } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const router = useRouter()
const loading = ref(false)
const incidents = ref<XdrIncident[]>([])
const totalCount = ref(0)

const filterSeverity = ref('')
const filterStatus = ref('')

function severityBadgeClass(severity: string): string {
  switch ((severity ?? '').toLowerCase()) {
    case 'critical': return 'bg-red-500/15 text-red-400'
    case 'high': return 'bg-orange-500/15 text-orange-400'
    case 'medium': return 'bg-yellow-500/15 text-yellow-400'
    case 'low': return 'bg-blue-500/15 text-blue-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function statusBadgeClass(status: string): string {
  switch ((status ?? '').toLowerCase()) {
    case 'new': return 'bg-blue-500/15 text-blue-400'
    case 'under_investigation': return 'bg-yellow-500/15 text-yellow-400'
    case 'resolved_true_positive': return 'bg-green-500/15 text-green-400'
    case 'resolved_false_positive': return 'bg-gray-500/15 text-gray-400'
    case 'resolved_known_issue':
    case 'resolved_duplicate':
    case 'resolved_other': return 'bg-teal-500/15 text-teal-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

const filteredIncidents = computed(() => {
  let result = incidents.value
  if (filterSeverity.value) {
    result = result.filter(i => (i.severity ?? '').toLowerCase() === filterSeverity.value)
  }
  if (filterStatus.value) {
    result = result.filter(i => (i.status ?? '').toLowerCase() === filterStatus.value)
  }
  return result
})

async function fetchIncidents(): Promise<void> {
  loading.value = true
  try {
    const res = await xdrIncidentsApi.list()
    incidents.value = res.reply?.incidents ?? []
    totalCount.value = res.reply?.total_count ?? incidents.value.length
  } finally {
    loading.value = false
  }
}

watch([filterSeverity, filterStatus], () => {
  // Client-side filtering, no refetch needed
})

onMounted(() => fetchIncidents())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="text-orange-500 font-bold">XDR</span> Incidents
        </h1>
        <p class="text-s1-muted text-sm">Cortex XDR incident management</p>
      </div>
      <button @click="fetchIncidents()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Filter bar -->
    <div class="card p-4 flex flex-wrap gap-3">
      <select v-model="filterSeverity" class="select">
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <select v-model="filterStatus" class="select">
        <option value="">All Statuses</option>
        <option value="new">New</option>
        <option value="under_investigation">Under Investigation</option>
        <option value="resolved_true_positive">Resolved - True Positive</option>
        <option value="resolved_false_positive">Resolved - False Positive</option>
        <option value="resolved_known_issue">Resolved - Known Issue</option>
        <option value="resolved_duplicate">Resolved - Duplicate</option>
        <option value="resolved_other">Resolved - Other</option>
      </select>
      <div class="ml-auto text-xs text-s1-muted self-center">
        {{ filteredIncidents.length }} of {{ totalCount }} incidents
      </div>
    </div>

    <!-- Table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">ID</th>
            <th class="table-header text-left">Description</th>
            <th class="table-header text-left">Severity</th>
            <th class="table-header text-left">Status</th>
            <th class="table-header text-left">Alerts</th>
            <th class="table-header text-left">Assigned To</th>
            <th class="table-header text-left">Created</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !incidents.length" :rows="8" />
          <template v-else>
            <tr
              v-for="inc in filteredIncidents" :key="inc.incident_id"
              class="table-row"
              @click="router.push(`/cortex-xdr/incidents/${inc.incident_id}`)"
            >
              <td class="table-cell">
                <span class="text-sm font-mono text-s1-text">{{ inc.incident_id }}</span>
              </td>
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm truncate max-w-[250px]">
                  {{ inc.description || `Incident ${inc.incident_id}` }}
                </div>
              </td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="severityBadgeClass(inc.severity)">
                  {{ inc.severity }}
                </span>
              </td>
              <td class="table-cell">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="statusBadgeClass(inc.status)">
                  {{ inc.status?.replace(/_/g, ' ') }}
                </span>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ inc.alert_count }}</td>
              <td class="table-cell text-sm text-s1-subtle truncate max-w-[120px]">
                {{ inc.assigned_user_pretty_name || inc.assigned_user_mail || '--' }}
              </td>
              <td class="table-cell text-xs text-s1-muted">{{ formatEpoch(inc.creation_time) }}</td>
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
