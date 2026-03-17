<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowLeft } from 'lucide-vue-next'
import { sentinelIncidentApi } from '../../api/sentinel'
import type { ArmResource, SentinelIncidentProps, SentinelAlertProps } from '../../types/sentinel'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

const route = useRoute()
const router = useRouter()
const id = route.params['id'] as string

const incident = ref<ArmResource<SentinelIncidentProps> | null>(null)
const alerts = ref<ArmResource<SentinelAlertProps>[]>([])
const entities = ref<unknown[]>([])
const comments = ref<ArmResource[]>([])
const loading = ref(true)
const actionLoading = ref(false)
const newComment = ref('')
const activeTab = ref('overview')

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'alerts', label: 'Alerts' },
  { id: 'entities', label: 'Entities' },
  { id: 'comments', label: 'Comments' },
]

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

function entityKindBadgeClass(kind: string): string {
  switch ((kind ?? '').toLowerCase()) {
    case 'account': return 'bg-blue-500/15 text-blue-400'
    case 'host': return 'bg-green-500/15 text-green-400'
    case 'ip': return 'bg-orange-500/15 text-orange-400'
    case 'url': return 'bg-purple-500/15 text-purple-400'
    case 'file': return 'bg-yellow-500/15 text-yellow-400'
    case 'process': return 'bg-cyan-500/15 text-cyan-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function updateStatus(newStatus: string): Promise<void> {
  if (!incident.value) return
  actionLoading.value = true
  try {
    const res = await sentinelIncidentApi.update(id, { status: newStatus })
    incident.value = res
  } finally {
    actionLoading.value = false
  }
}

async function fetchAlerts(): Promise<void> {
  try {
    const res = await sentinelIncidentApi.getAlerts(id)
    alerts.value = res.value ?? []
  } catch {
    alerts.value = []
  }
}

async function fetchEntities(): Promise<void> {
  try {
    const res = await sentinelIncidentApi.getEntities(id)
    entities.value = res.entities ?? []
  } catch {
    entities.value = []
  }
}

async function fetchComments(): Promise<void> {
  try {
    const res = await sentinelIncidentApi.getComments(id)
    comments.value = res.value ?? []
  } catch {
    comments.value = []
  }
}

async function addComment(): Promise<void> {
  if (!newComment.value.trim()) return
  actionLoading.value = true
  try {
    const commentId = crypto.randomUUID()
    await sentinelIncidentApi.addComment(id, commentId, newComment.value)
    newComment.value = ''
    await fetchComments()
  } finally {
    actionLoading.value = false
  }
}

onMounted(async () => {
  try {
    const [incRes] = await Promise.all([
      sentinelIncidentApi.get(id),
      fetchAlerts(),
      fetchEntities(),
      fetchComments(),
    ])
    incident.value = incRes
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <!-- Back -->
    <button @click="router.push('/sentinel/incidents')" class="btn-ghost flex items-center gap-2 mb-4 -ml-2">
      <ArrowLeft class="w-4 h-4" /> Sentinel Incidents
    </button>

    <div v-if="loading" class="card p-6"><LoadingSkeleton :rows="8" /></div>

    <div v-else-if="incident" class="grid grid-cols-3 gap-4">
      <!-- Left: Incident info card -->
      <div class="card p-5 space-y-4">
        <div>
          <h2 class="text-lg font-bold text-s1-text">{{ incident.properties.title }}</h2>
          <div class="flex items-center gap-2 mt-2">
            <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
              :class="statusBadgeClass(incident.properties.status)">
              {{ incident.properties.status }}
            </span>
            <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
              :class="severityBadgeClass(incident.properties.severity)">
              {{ incident.properties.severity }}
            </span>
          </div>
        </div>

        <!-- Actions -->
        <div class="space-y-2">
          <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider">Update Status</div>
          <div class="flex flex-wrap gap-2">
            <button v-if="incident.properties.status !== 'Active'" @click="updateStatus('Active')"
              :disabled="actionLoading"
              class="btn-ghost text-xs text-yellow-400">Set Active</button>
            <button v-if="incident.properties.status !== 'Closed'" @click="updateStatus('Closed')"
              :disabled="actionLoading"
              class="btn-ghost text-xs text-green-400">Close</button>
            <button v-if="incident.properties.status !== 'New'" @click="updateStatus('New')"
              :disabled="actionLoading"
              class="btn-ghost text-xs text-blue-400">Reopen</button>
          </div>
        </div>

        <div class="space-y-2 text-sm">
          <div v-for="[k, v] in [
            ['Title', incident.properties.title],
            ['Incident ID', incident.name],
            ['Severity', incident.properties.severity],
            ['Status', incident.properties.status],
            ['Owner', incident.properties.owner?.assignedTo || '--'],
            ['Provider', incident.properties.providerName],
            ['Incident Number', incident.properties.incidentNumber],
            ['Created', relativeTime(incident.properties.createdTimeUtc)],
            ['Modified', relativeTime(incident.properties.lastModifiedTimeUtc)],
          ]" :key="(k as string)" class="flex justify-between gap-2">
            <span class="text-s1-muted">{{ k }}</span>
            <span class="text-s1-text text-right truncate max-w-[60%] font-mono text-xs">{{ v ?? '--' }}</span>
          </div>

          <div v-if="incident.properties.labels?.length" class="pt-2">
            <div class="text-s1-muted text-xs mb-1.5">Labels</div>
            <div class="flex flex-wrap gap-1">
              <span v-for="label in incident.properties.labels" :key="label.labelName"
                class="text-xs px-2 py-0.5 rounded-full bg-green-600/20 text-green-400 font-medium">
                {{ label.labelName }}
              </span>
            </div>
          </div>

          <div v-if="incident.properties.additionalData?.tactics?.length" class="pt-2">
            <div class="text-s1-muted text-xs mb-1.5">Tactics</div>
            <div class="flex flex-wrap gap-1">
              <span v-for="tactic in incident.properties.additionalData.tactics" :key="tactic"
                class="text-xs px-2 py-0.5 rounded-full bg-orange-500/20 text-orange-400 font-medium">
                {{ tactic }}
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
              ? 'text-green-600 border-green-600'
              : 'text-s1-muted border-transparent hover:text-s1-text'"
          >
            {{ tab.label }}
            <span v-if="tab.id === 'alerts'" class="ml-1 text-xs text-s1-muted">({{ alerts.length }})</span>
            <span v-if="tab.id === 'entities'" class="ml-1 text-xs text-s1-muted">({{ entities.length }})</span>
            <span v-if="tab.id === 'comments'" class="ml-1 text-xs text-s1-muted">({{ comments.length }})</span>
          </button>
        </div>

        <div class="p-5 overflow-y-auto max-h-[70vh]">
          <!-- Overview -->
          <div v-if="activeTab === 'overview'" class="space-y-5">
            <div>
              <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-2">Incident Information</div>
              <div class="grid grid-cols-2 gap-x-6 gap-y-0 text-sm">
                <div v-for="[k, v] in [
                  ['Title', incident.properties.title],
                  ['Description', incident.properties.description],
                  ['Severity', incident.properties.severity],
                  ['Status', incident.properties.status],
                  ['Classification', incident.properties.classification || '--'],
                  ['Classification Reason', incident.properties.classificationReason || '--'],
                  ['Provider', incident.properties.providerName],
                  ['Provider Incident ID', incident.properties.providerIncidentId],
                  ['Incident Number', incident.properties.incidentNumber],
                  ['Alert Count', incident.properties.additionalData?.alertsCount ?? 0],
                  ['Owner', incident.properties.owner?.assignedTo || '--'],
                  ['Owner Email', incident.properties.owner?.email || '--'],
                  ['Created', relativeTime(incident.properties.createdTimeUtc)],
                  ['Modified', relativeTime(incident.properties.lastModifiedTimeUtc)],
                ]" :key="(k as string)" class="flex justify-between py-1.5 border-b border-s1-border/50">
                  <span class="text-s1-muted shrink-0">{{ k }}</span>
                  <span class="text-s1-text font-mono text-xs truncate max-w-[55%] text-right">{{ v ?? '--' }}</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Alerts -->
          <div v-else-if="activeTab === 'alerts'">
            <div v-if="alerts.length === 0" class="py-8 text-center text-s1-muted text-sm">
              No alerts for this incident
            </div>
            <table v-else class="w-full">
              <thead class="border-b border-s1-border">
                <tr>
                  <th class="table-header text-left">Alert Name</th>
                  <th class="table-header text-left">Severity</th>
                  <th class="table-header text-left">Product</th>
                  <th class="table-header text-left">Status</th>
                  <th class="table-header text-left">Generated</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="alert in alerts" :key="alert.name" class="table-row">
                  <td class="table-cell">
                    <div class="font-medium text-s1-text text-sm truncate max-w-[200px]">{{ alert.properties.alertDisplayName }}</div>
                    <div v-if="alert.properties.tactics?.length" class="text-xs text-s1-muted">
                      {{ alert.properties.tactics.join(', ') }}
                    </div>
                  </td>
                  <td class="table-cell">
                    <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                      :class="severityBadgeClass(alert.properties.severity)">
                      {{ alert.properties.severity }}
                    </span>
                  </td>
                  <td class="table-cell text-sm text-s1-subtle">{{ alert.properties.productName }}</td>
                  <td class="table-cell text-sm text-s1-subtle">{{ alert.properties.status }}</td>
                  <td class="table-cell text-xs text-s1-muted">{{ relativeTime(alert.properties.timeGenerated) }}</td>
                </tr>
              </tbody>
            </table>
          </div>

          <!-- Entities -->
          <div v-else-if="activeTab === 'entities'">
            <div v-if="entities.length === 0" class="py-8 text-center text-s1-muted text-sm">
              No entities for this incident
            </div>
            <div v-else class="space-y-2">
              <div v-for="(entity, idx) in entities" :key="idx"
                class="flex items-center gap-3 px-4 py-3 border border-s1-border rounded-lg hover:bg-s1-hover transition-colors">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="entityKindBadgeClass((entity as any).kind)">
                  {{ (entity as any).kind || 'Unknown' }}
                </span>
                <div class="text-sm text-s1-text">
                  {{ (entity as any).properties?.friendlyName || (entity as any).properties?.hostName || (entity as any).properties?.address || (entity as any).name || 'Entity' }}
                </div>
              </div>
            </div>
          </div>

          <!-- Comments -->
          <div v-else-if="activeTab === 'comments'" class="space-y-4">
            <div v-if="comments.length === 0 && !newComment" class="py-8 text-center text-s1-muted text-sm">
              No comments yet
            </div>
            <div v-for="comment in comments" :key="comment.name"
              class="border border-s1-border rounded-lg p-4">
              <div class="text-sm text-s1-text">{{ (comment.properties as any)?.message }}</div>
              <div class="text-xs text-s1-muted mt-2">
                {{ (comment.properties as any)?.author?.name || 'Unknown' }} &middot;
                {{ relativeTime((comment.properties as any)?.createdTimeUtc) }}
              </div>
            </div>

            <!-- Add comment form -->
            <div class="border-t border-s1-border pt-4">
              <textarea
                v-model="newComment"
                rows="3"
                placeholder="Add a comment..."
                class="w-full rounded-lg border border-s1-border bg-transparent text-s1-text text-sm p-3 focus:outline-none focus:border-green-600"
              ></textarea>
              <div class="flex justify-end mt-2">
                <button @click="addComment()" :disabled="actionLoading || !newComment.trim()"
                  class="btn-ghost text-sm text-green-600">
                  Add Comment
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div v-else class="card p-10 text-center">
      <p class="text-s1-muted">Incident not found</p>
      <button @click="router.push('/sentinel/incidents')" class="btn-ghost mt-4 text-sm">Back to incidents</button>
    </div>
  </div>
</template>
