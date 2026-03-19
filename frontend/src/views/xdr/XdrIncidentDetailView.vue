<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowLeft } from 'lucide-vue-next'
import { xdrIncidentsApi } from '../../api/cortex'
import type { XdrIncident, XdrAlert } from '../../types/cortex'
import { formatEpoch } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

const route = useRoute()
const router = useRouter()
const id = route.params['id'] as string

const incident = ref<XdrIncident | null>(null)
const linkedAlerts = ref<XdrAlert[]>([])
const loading = ref(true)
const actionLoading = ref(false)
const activeTab = ref('overview')

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'alerts', label: 'Linked Alerts' },
]

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
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function updateStatus(newStatus: string): Promise<void> {
  if (!incident.value) return
  actionLoading.value = true
  try {
    await xdrIncidentsApi.update(id, { status: newStatus })
    incident.value.status = newStatus
  } finally {
    actionLoading.value = false
  }
}

async function assignUser(): Promise<void> {
  if (!incident.value) return
  const email = prompt('Enter user email to assign:')
  if (!email) return
  actionLoading.value = true
  try {
    await xdrIncidentsApi.update(id, { assigned_user_mail: email })
    incident.value.assigned_user_mail = email
  } finally {
    actionLoading.value = false
  }
}

onMounted(async () => {
  try {
    const res = await xdrIncidentsApi.getExtraData(id)
    const data = res.reply
    incident.value = data?.incident ?? null
    linkedAlerts.value = data?.alerts?.data ?? []
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <!-- Back -->
    <button @click="router.push('/cortex-xdr/incidents')" class="btn-ghost flex items-center gap-2 mb-4 -ml-2">
      <ArrowLeft class="w-4 h-4" /> XDR Incidents
    </button>

    <div v-if="loading" class="card p-6"><LoadingSkeleton :rows="8" /></div>

    <div v-else-if="incident" class="grid grid-cols-3 gap-4">
      <!-- Left: Incident info card -->
      <div class="card p-5 space-y-4">
        <div>
          <h2 class="text-lg font-bold text-s1-text">{{ incident.description || `Incident ${incident.incident_id}` }}</h2>
          <div class="flex items-center gap-2 mt-2">
            <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
              :class="statusBadgeClass(incident.status)">
              {{ incident.status?.replace(/_/g, ' ') }}
            </span>
            <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
              :class="severityBadgeClass(incident.severity)">
              {{ incident.severity }}
            </span>
          </div>
        </div>

        <!-- Actions -->
        <div class="space-y-2">
          <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider">Actions</div>
          <div class="flex flex-wrap gap-2">
            <button v-if="incident.status === 'new'" @click="updateStatus('under_investigation')"
              :disabled="actionLoading"
              class="btn-ghost text-xs text-yellow-400">Investigate</button>
            <button v-if="!incident.status?.startsWith('resolved')" @click="updateStatus('resolved_true_positive')"
              :disabled="actionLoading"
              class="btn-ghost text-xs text-green-400">Resolve (TP)</button>
            <button v-if="!incident.status?.startsWith('resolved')" @click="updateStatus('resolved_false_positive')"
              :disabled="actionLoading"
              class="btn-ghost text-xs text-gray-400">Resolve (FP)</button>
            <button @click="assignUser()" :disabled="actionLoading"
              class="btn-ghost text-xs text-blue-400">Assign User</button>
          </div>
        </div>

        <div class="space-y-2 text-sm">
          <div v-for="[k, v] in [
            ['Incident ID', incident.incident_id],
            ['Severity', incident.severity],
            ['Status', incident.status?.replace(/_/g, ' ')],
            ['Alert Count', incident.alert_count],
            ['Score', incident.rule_based_score],
            ['Assigned To', incident.assigned_user_pretty_name || incident.assigned_user_mail || '--'],
            ['Created', formatEpoch(incident.creation_time)],
            ['Modified', formatEpoch(incident.modification_time)],
          ]" :key="(k as string)" class="flex justify-between gap-2">
            <span class="text-s1-muted">{{ k }}</span>
            <span class="text-s1-text text-right truncate max-w-[60%] font-mono text-xs">{{ v ?? '--' }}</span>
          </div>

          <div v-if="incident.hosts?.length" class="pt-2">
            <div class="text-s1-muted text-xs mb-1.5">Hosts</div>
            <div class="flex flex-wrap gap-1">
              <span v-for="host in incident.hosts" :key="host"
                class="text-xs px-2 py-0.5 rounded-full bg-orange-500/20 text-orange-400 font-medium">
                {{ host }}
              </span>
            </div>
          </div>

          <div v-if="incident.users?.length" class="pt-2">
            <div class="text-s1-muted text-xs mb-1.5">Users</div>
            <div class="flex flex-wrap gap-1">
              <span v-for="user in incident.users" :key="user"
                class="text-xs px-2 py-0.5 rounded-full bg-blue-500/20 text-blue-400 font-medium">
                {{ user }}
              </span>
            </div>
          </div>

          <div v-if="incident.incident_sources?.length" class="pt-2">
            <div class="text-s1-muted text-xs mb-1.5">Sources</div>
            <div class="flex flex-wrap gap-1">
              <span v-for="src in incident.incident_sources" :key="src"
                class="text-xs px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-400 font-medium">
                {{ src }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- Right: Tabs -->
      <div class="col-span-2 card overflow-hidden">
        <div class="flex border-b border-s1-border overflow-x-auto">
          <button
            v-for="tab in TABS" :key="tab.id"
            @click="activeTab = tab.id"
            class="px-4 py-3 text-sm font-medium transition-colors border-b-2 -mb-px whitespace-nowrap"
            :class="activeTab === tab.id
              ? 'text-orange-400 border-orange-500'
              : 'text-s1-muted border-transparent hover:text-s1-text'"
          >
            {{ tab.label }}
            <span v-if="tab.id === 'alerts'" class="ml-1 text-xs text-s1-muted">({{ linkedAlerts.length }})</span>
          </button>
        </div>

        <div class="p-5 overflow-y-auto max-h-[70vh]">
          <!-- Overview -->
          <div v-if="activeTab === 'overview'" class="space-y-5">
            <div>
              <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-2">Incident Information</div>
              <div class="grid grid-cols-2 gap-x-6 gap-y-0 text-sm">
                <div v-for="[k, v] in [
                  ['Incident ID', incident.incident_id],
                  ['Description', incident.description],
                  ['Severity', incident.severity],
                  ['Status', incident.status?.replace(/_/g, ' ')],
                  ['Alert Count', incident.alert_count],
                  ['Rule Score', incident.rule_based_score],
                  ['Manual Severity', incident.manual_severity || '--'],
                  ['Starred', incident.starred ? 'Yes' : 'No'],
                  ['Assigned User', incident.assigned_user_pretty_name || '--'],
                  ['Assigned Email', incident.assigned_user_mail || '--'],
                  ['Created', formatEpoch(incident.creation_time)],
                  ['Modified', formatEpoch(incident.modification_time)],
                ]" :key="(k as string)" class="flex justify-between py-1.5 border-b border-s1-border/50">
                  <span class="text-s1-muted shrink-0">{{ k }}</span>
                  <span class="text-s1-text font-mono text-xs truncate max-w-[55%] text-right">{{ v ?? '--' }}</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Linked Alerts -->
          <div v-else-if="activeTab === 'alerts'">
            <div v-if="linkedAlerts.length === 0" class="py-8 text-center text-s1-muted text-sm">
              No linked alerts for this incident
            </div>
            <table v-else class="w-full">
              <thead class="border-b border-s1-border">
                <tr>
                  <th class="table-header text-left">Name</th>
                  <th class="table-header text-left">Severity</th>
                  <th class="table-header text-left">Source</th>
                  <th class="table-header text-left">Host</th>
                  <th class="table-header text-left">Detected</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="alert in linkedAlerts" :key="alert.alert_id" class="table-row">
                  <td class="table-cell">
                    <div class="font-medium text-s1-text text-sm truncate max-w-[200px]">{{ alert.name }}</div>
                    <div class="text-xs text-s1-muted">{{ alert.category }}</div>
                  </td>
                  <td class="table-cell">
                    <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                      :class="severityBadgeClass(alert.severity)">
                      {{ alert.severity }}
                    </span>
                  </td>
                  <td class="table-cell text-sm text-s1-subtle">{{ alert.source }}</td>
                  <td class="table-cell text-sm text-s1-subtle">{{ alert.host_name }}</td>
                  <td class="table-cell text-xs text-s1-muted">{{ formatEpoch(alert.detection_timestamp) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <div v-else class="card p-10 text-center">
      <p class="text-s1-muted">Incident not found</p>
      <button @click="router.push('/cortex-xdr/incidents')" class="btn-ghost mt-4 text-sm">Back to incidents</button>
    </div>
  </div>
</template>
