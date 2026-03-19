<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowLeft, Plus } from 'lucide-vue-next'
import { threatsApi } from '../api/threats'
import StatusBadge from '../components/shared/StatusBadge.vue'
import LoadingSkeleton from '../components/shared/LoadingSkeleton.vue'
import type { ThreatRecord } from '../types'

interface TimelineEvent { id: string; timestamp: string; event: string; type: string }
interface ThreatNote { id: string; text: string; createdAt: string }
interface MitigationAction { mitigate?: string; incident?: string; label: string }

const route = useRoute()
const router = useRouter()
const threat = ref<ThreatRecord | null>(null)
const timeline = ref<TimelineEvent[]>([])
const notes = ref<ThreatNote[]>([])
const newNote = ref('')
const activeTab = ref('overview')
const loading = ref(true)
const actionLoading = ref(false)
const submittingNote = ref(false)
const error = ref('')

const id = route.params['id'] as string

onMounted(async () => {
  try {
    const [threatRes, timelineRes, notesRes] = await Promise.all([
      threatsApi.get(id),
      threatsApi.timeline(id),
      threatsApi.getNotes(id),
    ])
    threat.value = threatRes.data
    timeline.value = timelineRes.data
    notes.value = notesRes.data
  } finally {
    loading.value = false
  }
})

async function doVerdict(verdict: string): Promise<void> {
  actionLoading.value = true
  try {
    await threatsApi.setVerdict([id], verdict)
    const res = await threatsApi.get(id)
    threat.value = res.data
  } finally {
    actionLoading.value = false
  }
}

async function doMitigate(act: MitigationAction): Promise<void> {
  actionLoading.value = true
  try {
    if (act.mitigate) {
      await threatsApi.mitigate(act.mitigate, [id])
    } else if (act.incident) {
      await threatsApi.setIncident([id], act.incident)
    }
    const res = await threatsApi.get(id)
    threat.value = res.data
  } finally {
    actionLoading.value = false
  }
}

async function submitNote(): Promise<void> {
  if (!newNote.value.trim()) return
  submittingNote.value = true
  error.value = ''
  try {
    const res = await threatsApi.addNote(id, newNote.value)
    notes.value.push(res.data)
    newNote.value = ''
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : 'Failed to add note'
  } finally {
    submittingNote.value = false
  }
}

const TABS = ['overview', 'timeline', 'file', 'notes', 'agent']

const VERDICT_OPTIONS = [
  { verdict: 'undefined',      label: 'Undefined'      },
  { verdict: 'suspicious',     label: 'Suspicious'     },
  { verdict: 'false_positive', label: 'False Positive' },
  { verdict: 'true_positive',  label: 'True Positive'  },
]

const MITIGATION_ACTIONS = computed<MitigationAction[]>(() => {
  const s = threat.value?.threatInfo.mitigationStatus
  return [
    s === 'quarantined'
      ? { mitigate: 'un-quarantine', label: 'Un-quarantine' }
      : { mitigate: 'quarantine',    label: 'Quarantine'    },
    { mitigate: 'kill',      label: 'Kill'      },
    { mitigate: 'remediate', label: 'Remediate' },
    threat.value?.threatInfo.resolved
      ? { incident: 'unresolved', label: 'Re-open' }
      : { incident: 'resolved',   label: 'Resolve' },
  ]
})
</script>

<template>
  <div>
    <button @click="router.push('/threats')" class="btn-ghost flex items-center gap-2 mb-4 -ml-2">
      <ArrowLeft class="w-4 h-4" /> Threats
    </button>

    <div v-if="error" class="error-banner">{{ error }}</div>

    <div v-if="loading"><LoadingSkeleton :rows="8" /></div>

    <div v-else-if="threat" class="space-y-4">
      <!-- Header card -->
      <div class="card p-5">
        <div class="flex items-start justify-between">
          <div>
            <h1 class="text-xl font-bold text-s1-text mb-2">{{ threat.threatInfo.threatName }}</h1>
            <div class="flex items-center gap-3 flex-wrap">
              <StatusBadge :status="threat.threatInfo.mitigationStatus" type="threat" />
              <StatusBadge :status="threat.threatInfo.incidentStatus" type="incident" />
              <StatusBadge :status="threat.threatInfo.analystVerdict" type="verdict" />
              <span class="text-sm text-s1-muted">{{ threat.threatInfo.classification }}</span>
              <span class="text-sm text-s1-muted">{{ threat.threatInfo.confidenceLevel }}</span>
            </div>
          </div>
          <!-- Actions -->
          <div class="flex flex-col items-end gap-2">
            <!-- Analyst verdict toggle -->
            <div class="flex rounded-lg overflow-hidden border border-s1-border text-xs">
              <button
                v-for="opt in VERDICT_OPTIONS" :key="opt.verdict"
                @click="doVerdict(opt.verdict)"
                :disabled="actionLoading"
                class="px-3 py-1.5 transition-colors"
                :class="threat.threatInfo.analystVerdict === opt.verdict
                  ? 'bg-s1-primary text-white font-medium'
                  : 'text-s1-muted hover:text-s1-text hover:bg-s1-hover'"
              >
                {{ opt.label }}
              </button>
            </div>
            <!-- Mitigation + resolve -->
            <div class="flex gap-1.5">
              <button
                v-for="act in MITIGATION_ACTIONS" :key="act.mitigate ?? act.incident"
                @click="doMitigate(act)"
                :disabled="actionLoading"
                class="btn-ghost text-xs py-1"
              >
                {{ act.label }}
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Tabs -->
      <div class="card overflow-hidden">
        <div class="flex border-b border-s1-border">
          <button
            v-for="tab in TABS" :key="tab"
            @click="activeTab = tab"
            class="px-5 py-3 text-sm font-medium capitalize transition-colors border-b-2 -mb-px"
            :class="activeTab === tab
              ? 'text-s1-primary border-s1-primary'
              : 'text-s1-muted border-transparent hover:text-s1-text'"
          >
            {{ tab }}
          </button>
        </div>

        <div class="p-5">
          <!-- Overview -->
          <div v-if="activeTab === 'overview'" class="grid grid-cols-2 gap-x-8 gap-y-2 text-sm">
            <div v-for="[k, v] in [
              ['Site', threat.agentDetectionInfo.siteName],
              ['Group', threat.agentDetectionInfo.groupName],
              ['Detection Source', threat.threatInfo.classificationSource],
              ['Engines', threat.threatInfo.engines?.join(', ')],
              ['Initiated By', threat.threatInfo.initiatedBy],
              ['Created', threat.threatInfo.createdAt?.slice(0, 19).replace('T', ' ')],
              ['Updated', threat.threatInfo.updatedAt?.slice(0, 19).replace('T', ' ')],
              ['Storyline ID', threat.threatInfo.storylineId],
            ]" :key="(k as string)" class="flex justify-between py-1.5 border-b border-s1-border/50">
              <span class="text-s1-muted">{{ k }}</span>
              <span class="text-s1-text text-right text-xs truncate max-w-[60%]">{{ v }}</span>
            </div>
          </div>

          <!-- Timeline -->
          <div v-else-if="activeTab === 'timeline'">
            <div class="relative">
              <div class="absolute left-3 top-0 bottom-0 w-px bg-s1-border"></div>
              <div v-for="event in timeline" :key="event.id" class="relative pl-8 pb-6">
                <div class="absolute left-1.5 w-3 h-3 rounded-full bg-s1-primary border-2 border-s1-bg"></div>
                <div class="text-xs text-s1-muted mb-1">{{ event.timestamp?.slice(0, 19).replace('T', ' ') }}</div>
                <div class="text-sm text-s1-text">{{ event.event }}</div>
                <div class="text-xs text-s1-muted capitalize">{{ event.type }}</div>
              </div>
            </div>
          </div>

          <!-- File -->
          <div v-else-if="activeTab === 'file'" class="space-y-2 text-sm">
            <div v-for="[k, v] in [
              ['File Name', threat.threatInfo.fileName],
              ['File Path', threat.threatInfo.filePath],
              ['File Size', threat.threatInfo.fileSize ? `${(threat.threatInfo.fileSize / 1024).toFixed(1)} KB` : '—'],
              ['SHA1', threat.threatInfo.sha1],
              ['SHA256', threat.threatInfo.sha256],
              ['MD5', threat.threatInfo.md5],
            ]" :key="(k as string)" class="flex flex-col gap-0.5 py-2 border-b border-s1-border/50">
              <span class="text-s1-muted text-xs">{{ k }}</span>
              <span class="font-mono text-xs text-s1-text break-all">{{ v }}</span>
            </div>
          </div>

          <!-- Notes -->
          <div v-else-if="activeTab === 'notes'" class="space-y-3">
            <div v-if="!notes.length" class="text-center py-6 text-s1-muted text-sm">No notes yet</div>
            <div v-else v-for="note in notes" :key="note.id"
              class="p-3 bg-s1-bg rounded-lg text-sm text-s1-text border border-s1-border">
              <div class="mb-1">{{ note.text }}</div>
              <div class="text-xs text-s1-muted">{{ note.createdAt?.slice(0, 10) }}</div>
            </div>
            <div class="flex gap-2 mt-4">
              <input v-model="newNote" class="input flex-1" placeholder="Add a note..." @keyup.enter="submitNote" />
              <button @click="submitNote" :disabled="submittingNote" class="btn-primary flex items-center gap-1.5 text-xs disabled:opacity-50">
                <Plus class="w-3.5 h-3.5" /> {{ submittingNote ? 'Adding...' : 'Add' }}
              </button>
            </div>
          </div>

          <!-- Agent -->
          <div v-else-if="activeTab === 'agent'" class="space-y-2 text-sm">
            <div v-for="[k, v] in [
              ['Computer Name', threat.agentDetectionInfo.agentComputerName],
              ['Agent Version', threat.agentDetectionInfo.agentVersion],
              ['OS', threat.agentDetectionInfo.agentOsName],
              ['Local IP', threat.agentDetectionInfo.agentIpV4],
              ['External IP', threat.agentDetectionInfo.externalIp],
              ['Domain', threat.agentDetectionInfo.agentDomain],
              ['Last User', threat.agentDetectionInfo.agentLastLoggedInUserName],
            ]" :key="(k as string)" class="flex justify-between py-1.5 border-b border-s1-border/50">
              <span class="text-s1-muted">{{ k }}</span>
              <span class="text-s1-text text-xs font-mono">{{ v }}</span>
            </div>
            <div class="pt-2">
              <RouterLink :to="`/endpoints/${threat.agentRealtimeInfo.agentId}`" class="text-s1-primary text-sm hover:underline">
                View endpoint →
              </RouterLink>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
