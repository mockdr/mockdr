<!--
  PlaybookView — Playbook library: run pre-built or custom incident simulations,
  and manage the full lifecycle of playbooks (create, edit, delete).

  Layout: fixed left library panel + right panel that switches between
  the run view (default) and the editor panel (create / edit mode).
-->
<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import {
  Play, Square, CheckCircle, AlertTriangle, Zap, Shield, RefreshCw, Activity,
  Plus, Pencil, Trash2, GripVertical, X,
} from 'lucide-vue-next'
import axios from 'axios'
import client from '../api/client'

// ── Types ──────────────────────────────────────────────────────────────────────

interface PlaybookMeta {
  id: string
  title: string
  description: string
  category: string
  severity: string
  estimatedDurationMs: number
  stepCount: number
  builtin: boolean
}

interface PlaybookStep {
  stepId: string
  label: string
  delayMs: number
  action: string
  // activity
  activityType?: number
  description?: string
  // threat
  threatName?: string
  fileName?: string
  classification?: string
  confidenceLevel?: string
  mitreTactic?: string
  mitreTechnique?: string
  sha1?: string
  // alert
  severity?: string
  category?: string
  // agent_state
  infected?: boolean
  activeThreats?: number
  networkStatus?: string
}

interface PlaybookDraft {
  id: string
  title: string
  description: string
  category: string
  severity: string
  estimatedDurationMs: number
  steps: PlaybookStep[]
}

interface StepStatus {
  stepId: string
  status: 'pending' | 'running' | 'done' | 'error'
  startedAt: string | null
  completedAt: string | null
  error: string | null
}

interface RunStatus {
  status: 'idle' | 'running' | 'done' | 'cancelled' | 'error'
  playbookId?: string
  agentId?: string
  currentStep?: number
  totalSteps?: number
  startedAt?: string
  completedAt?: string
  steps?: StepStatus[]
}

interface Agent {
  id: string
  computerName: string
}

interface PlaybookDetail {
  id: string
  title: string
  steps: PlaybookStep[]
}

// ── State ──────────────────────────────────────────────────────────────────────

const playbooks = ref<PlaybookMeta[]>([])
const agents = ref<Agent[]>([])
const selected = ref<PlaybookMeta | null>(null)
const detail = ref<PlaybookDetail | null>(null)
const selectedAgentId = ref<string>('')
const runStatus = ref<RunStatus>({ status: 'idle' })
const loading = ref(false)
const pollingTimer = ref<number | null>(null)

/** null = run view; non-null = editor open for this draft */
const editing = ref<PlaybookDraft | null>(null)
const saving = ref(false)
/** ID awaiting double-click delete confirmation */
const deleteConfirmId = ref<string | null>(null)
/** Index of the step being dragged */
const dragSrcIdx = ref<number | null>(null)

function devHeaders() {
  return { Authorization: `ApiToken ${localStorage.getItem('s1_token') ?? ''}` }
}

// ── Derived / helpers ──────────────────────────────────────────────────────────

const categoryIcon = (cat: string) => (
  ({ malware: Shield, ransomware: AlertTriangle, lateral: Zap, reset: RefreshCw } as Record<string, unknown>)[cat] ?? Activity
)

const categoryColor = (cat: string) => (
  ({ malware: 'text-orange-400', ransomware: 'text-red-400', lateral: 'text-yellow-400', reset: 'text-green-400' } as Record<string, string>)[cat] ?? 'text-s1-muted'
)

const severityBadge = (sev: string) => (
  ({
    CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/30',
    HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    LOW: 'bg-green-500/20 text-green-400 border-green-500/30',
  } as Record<string, string>)[sev] ?? 'bg-s1-border/20 text-s1-muted'
)

const stepStatusColor = (s: string) => (
  ({ done: 'text-green-400', running: 'text-blue-400 animate-pulse', error: 'text-red-400', pending: 'text-s1-muted' } as Record<string, string>)[s] ?? 'text-s1-muted'
)

const stepStatusIcon = (s: string) => (
  ({ done: '✓', running: '◐', error: '✗', pending: '○' } as Record<string, string>)[s] ?? '○'
)

const isRunning = computed(() => runStatus.value.status === 'running')

const progress = computed(() => {
  const steps = runStatus.value.steps
  if (!steps?.length) return 0
  return Math.round((steps.filter(s => s.status === 'done').length / steps.length) * 100)
})

function formatDelay(ms: number): string {
  if (ms === 0) return 'immediately'
  if (ms < 1000) return `${ms}ms`
  return `t+${ms / 1000}s`
}

function elapsedSeconds(startedAt: string | null): string {
  if (!startedAt) return ''
  return `${((Date.now() - new Date(startedAt).getTime()) / 1000).toFixed(1)}s ago`
}

// ── API calls ──────────────────────────────────────────────────────────────────

async function loadPlaybooks(): Promise<void> {
  const r = await axios.get('/_dev/playbooks', { headers: devHeaders() })
  playbooks.value = r.data.data
}

async function loadAgents(): Promise<void> {
  const r = await client.get('/agents', { params: { limit: 100 } }) as { data: Agent[] }
  agents.value = r.data
  if (agents.value.length && !selectedAgentId.value) {
    selectedAgentId.value = agents.value[0].id
  }
}

async function selectPlaybook(p: PlaybookMeta): Promise<void> {
  if (editing.value) return
  selected.value = p
  const r = await axios.get(`/_dev/playbooks/${p.id}`, { headers: devHeaders() })
  detail.value = r.data.data
}

async function runPlaybook(): Promise<void> {
  if (!selected.value || !selectedAgentId.value || isRunning.value) return
  loading.value = true
  try {
    await axios.post(`/_dev/playbooks/${selected.value.id}/run`, { agentId: selectedAgentId.value }, { headers: devHeaders() })
    startPolling()
  } finally {
    loading.value = false
  }
}

async function cancelRun(): Promise<void> {
  await axios.delete('/_dev/playbooks/cancel', { headers: devHeaders() })
  stopPolling()
  await pollStatus()
}

async function pollStatus(): Promise<void> {
  try {
    const r = await axios.get('/_dev/playbooks/status', { headers: devHeaders() })
    runStatus.value = r.data.data ?? { status: 'idle' }
  } catch {
    // ignore transient poll errors
  }
}

function startPolling(): void {
  stopPolling()
  pollingTimer.value = window.setInterval(async () => {
    await pollStatus()
    if (runStatus.value.status !== 'running') stopPolling()
  }, 500)
}

function stopPolling(): void {
  if (pollingTimer.value) {
    clearInterval(pollingTimer.value)
    pollingTimer.value = null
  }
}

// ── CRUD actions ───────────────────────────────────────────────────────────────

function openCreate(): void {
  editing.value = {
    id: '',
    title: '',
    description: '',
    category: 'custom',
    severity: 'MEDIUM',
    estimatedDurationMs: 10000,
    steps: [],
  }
}

async function openEdit(p: PlaybookMeta, e: MouseEvent): Promise<void> {
  e.stopPropagation()
  const r = await axios.get(`/_dev/playbooks/${p.id}`, { headers: devHeaders() })
  editing.value = { ...r.data.data, steps: r.data.data.steps.map((s: PlaybookStep) => ({ ...s })) }
}

function cancelEdit(): void {
  editing.value = null
}

async function savePlaybook(): Promise<void> {
  if (!editing.value) return
  saving.value = true
  try {
    const draft = editing.value
    if (draft.id) {
      await axios.put(`/_dev/playbooks/${draft.id}`, draft, { headers: devHeaders() })
    } else {
      const r = await axios.post('/_dev/playbooks', draft, { headers: devHeaders() })
      draft.id = r.data.data.id
    }
    await loadPlaybooks()
    editing.value = null
  } finally {
    saving.value = false
  }
}

async function requestDelete(id: string, e: MouseEvent): Promise<void> {
  e.stopPropagation()
  if (deleteConfirmId.value === id) {
    deleteConfirmId.value = null
    await axios.delete(`/_dev/playbooks/${id}`, { headers: devHeaders() })
    if (selected.value?.id === id) { selected.value = null; detail.value = null }
    await loadPlaybooks()
  } else {
    deleteConfirmId.value = id
    setTimeout(() => { if (deleteConfirmId.value === id) deleteConfirmId.value = null }, 3000)
  }
}

// ── Step editor helpers ────────────────────────────────────────────────────────

function addStep(): void {
  if (!editing.value) return
  editing.value.steps.push({
    stepId: `step_${editing.value.steps.length + 1}`,
    label: '',
    delayMs: 0,
    action: 'activity',
    activityType: 2,
    description: '',
  })
}

function removeStep(idx: number): void {
  editing.value?.steps.splice(idx, 1)
}

function onStepActionChange(idx: number, action: string): void {
  const step = editing.value?.steps[idx]
  if (!step) return
  const base: PlaybookStep = { stepId: step.stepId, label: step.label, delayMs: step.delayMs, action }
  if (action === 'activity')    Object.assign(base, { activityType: 2, description: '' })
  if (action === 'threat')      Object.assign(base, { threatName: '', fileName: '', classification: 'Trojan', confidenceLevel: 'malicious', mitreTactic: '', mitreTechnique: '', sha1: '' })
  if (action === 'alert')       Object.assign(base, { severity: 'HIGH', category: 'Malware', description: '', mitreTactic: '', mitreTechnique: '' })
  if (action === 'agent_state') Object.assign(base, { infected: true, activeThreats: 1, networkStatus: 'connected' })
  editing.value!.steps[idx] = base
}

function onDragStart(idx: number): void { dragSrcIdx.value = idx }

function onDrop(toIdx: number): void {
  if (dragSrcIdx.value === null || !editing.value) return
  const steps = editing.value.steps
  const [moved] = steps.splice(dragSrcIdx.value, 1)
  steps.splice(toIdx, 0, moved)
  dragSrcIdx.value = null
}

// ── Lifecycle ──────────────────────────────────────────────────────────────────

onMounted(() => {
  loadPlaybooks()
  loadAgents()
  pollStatus()
})

onUnmounted(stopPolling)
</script>

<template>
  <div class="flex h-full bg-s1-bg text-s1-text overflow-hidden">

    <!-- ── Left: Playbook Library ──────────────────────────────────────────── -->
    <div class="w-80 flex-shrink-0 border-r border-s1-border flex flex-col">
      <div class="p-4 border-b border-s1-border flex items-center justify-between">
        <div>
          <h2 class="text-sm font-semibold text-s1-muted uppercase tracking-wider">Playbook Library</h2>
          <p class="text-xs text-s1-muted mt-1">Pre-built incident simulations</p>
        </div>
        <button
          @click="openCreate"
          class="flex items-center gap-1 px-2.5 py-1.5 bg-s1-accent hover:bg-s1-primary text-white rounded-lg text-xs font-medium transition-colors"
        >
          <Plus class="w-3 h-3" />
          New
        </button>
      </div>

      <div class="flex-1 overflow-y-auto p-3 space-y-2">
        <div v-for="p in playbooks" :key="p.id" class="relative group">
          <button
            @click="selectPlaybook(p)"
            :class="[
              'w-full text-left p-3 rounded-lg border transition-all duration-150',
              selected?.id === p.id && !editing
                ? 'bg-s1-accent/20 border-blue-500/50 ring-1 ring-blue-500/30'
                : 'bg-s1-card border-s1-border hover:border-s1-border hover:bg-s1-bg/50',
            ]"
          >
            <div class="flex items-start gap-3">
              <component :is="categoryIcon(p.category)" class="w-4 h-4 mt-0.5 flex-shrink-0" :class="categoryColor(p.category)" />
              <div class="min-w-0 flex-1 pr-10">
                <div class="font-medium text-sm text-s1-text leading-tight truncate">{{ p.title }}</div>
                <div class="text-xs text-s1-muted mt-1 line-clamp-2 leading-relaxed">{{ p.description }}</div>
                <div class="flex items-center gap-2 mt-2 flex-wrap">
                  <span :class="['text-xs px-1.5 py-0.5 rounded border font-medium', severityBadge(p.severity)]">{{ p.severity }}</span>
                  <span class="text-xs text-s1-muted">{{ p.stepCount }} steps</span>
                  <span v-if="!p.builtin" class="text-xs px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-400 border border-purple-500/30">custom</span>
                </div>
              </div>
            </div>
          </button>

          <!-- Edit / Delete overlay -->
          <div class="absolute top-2 right-2 flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
            <button
              @click="openEdit(p, $event)"
              class="p-1 rounded bg-s1-bg hover:bg-s1-hover text-s1-muted hover:text-s1-text transition-colors"
              title="Edit playbook"
            >
              <Pencil class="w-3 h-3" />
            </button>
            <button
              @click="requestDelete(p.id, $event)"
              :class="[
                'p-1 rounded transition-colors',
                deleteConfirmId === p.id
                  ? 'bg-s1-danger text-white'
                  : 'bg-s1-bg hover:bg-s1-danger/50 text-s1-muted hover:text-s1-danger',
              ]"
              :title="deleteConfirmId === p.id ? 'Click again to confirm' : 'Delete playbook'"
            >
              <Trash2 class="w-3 h-3" />
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- ── Right: Editor Panel ─────────────────────────────────────────────── -->
    <div v-if="editing" class="flex-1 flex flex-col overflow-hidden">
      <div class="p-6 border-b border-s1-border flex items-center justify-between flex-shrink-0">
        <h1 class="text-xl font-semibold text-s1-text">
          {{ editing.id ? 'Edit Playbook' : 'New Playbook' }}
        </h1>
        <div class="flex gap-2">
          <button
            @click="cancelEdit"
            class="flex items-center gap-1.5 px-3 py-2 border border-s1-border rounded-lg text-sm text-s1-muted hover:text-s1-text transition-colors"
          >
            <X class="w-4 h-4" /> Cancel
          </button>
          <button
            @click="savePlaybook"
            :disabled="saving || !editing.title"
            class="px-4 py-2 bg-s1-accent hover:bg-s1-primary disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors"
          >
            {{ saving ? 'Saving…' : 'Save' }}
          </button>
        </div>
      </div>

      <div class="flex-1 overflow-y-auto p-6 space-y-6">
        <!-- Metadata -->
        <div class="grid grid-cols-2 gap-4">
          <div class="col-span-2">
            <label class="block text-xs font-medium text-s1-muted mb-1.5">Title</label>
            <input
              v-model="editing.title"
              placeholder="Playbook title"
              class="w-full bg-s1-card border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text focus:outline-none focus:border-s1-primary"
            />
          </div>
          <div class="col-span-2">
            <label class="block text-xs font-medium text-s1-muted mb-1.5">Description</label>
            <textarea
              v-model="editing.description"
              rows="2"
              placeholder="What does this playbook simulate?"
              class="w-full bg-s1-card border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text focus:outline-none focus:border-s1-primary resize-none"
            />
          </div>
          <div>
            <label class="block text-xs font-medium text-s1-muted mb-1.5">Category</label>
            <select v-model="editing.category" class="w-full bg-s1-card border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text focus:outline-none focus:border-s1-primary">
              <option value="malware">malware</option>
              <option value="ransomware">ransomware</option>
              <option value="lateral">lateral</option>
              <option value="reset">reset</option>
              <option value="custom">custom</option>
            </select>
          </div>
          <div>
            <label class="block text-xs font-medium text-s1-muted mb-1.5">Severity</label>
            <select v-model="editing.severity" class="w-full bg-s1-card border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text focus:outline-none focus:border-s1-primary">
              <option>CRITICAL</option>
              <option>HIGH</option>
              <option>MEDIUM</option>
              <option>LOW</option>
            </select>
          </div>
          <div>
            <label class="block text-xs font-medium text-s1-muted mb-1.5">Duration (ms)</label>
            <input
              v-model.number="editing.estimatedDurationMs"
              type="number" min="0" step="1000"
              class="w-full bg-s1-card border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text focus:outline-none focus:border-s1-primary"
            />
          </div>
        </div>

        <!-- Steps -->
        <div>
          <div class="flex items-center justify-between mb-3">
            <h3 class="text-xs font-semibold text-s1-muted uppercase tracking-wider">Steps</h3>
            <button
              @click="addStep"
              class="flex items-center gap-1 px-2.5 py-1 bg-s1-bg hover:bg-s1-hover border border-s1-border rounded-lg text-xs text-s1-muted hover:text-s1-text transition-colors"
            >
              <Plus class="w-3 h-3" /> Add Step
            </button>
          </div>

          <div class="space-y-2">
            <div
              v-for="(step, idx) in editing.steps"
              :key="idx"
              draggable="true"
              @dragstart="onDragStart(idx)"
              @dragover.prevent
              @drop.prevent="onDrop(idx)"
              :class="['rounded-lg border bg-s1-card transition-colors', dragSrcIdx === idx ? 'border-blue-500/50 opacity-40' : 'border-s1-border']"
            >
              <!-- Step row -->
              <div class="flex items-center gap-2 p-2.5">
                <GripVertical class="w-4 h-4 text-s1-muted cursor-grab flex-shrink-0" />
                <span class="text-xs text-s1-muted w-4 text-center flex-shrink-0">{{ idx + 1 }}</span>
                <input
                  v-model="step.stepId"
                  placeholder="stepId"
                  class="w-28 bg-s1-bg border border-s1-border rounded px-2 py-1 text-xs text-s1-subtle font-mono focus:outline-none focus:border-s1-primary"
                />
                <input
                  v-model="step.label"
                  placeholder="Label"
                  class="flex-1 bg-s1-bg border border-s1-border rounded px-2 py-1 text-xs text-s1-subtle focus:outline-none focus:border-s1-primary min-w-0"
                />
                <input
                  v-model.number="step.delayMs"
                  type="number" min="0" step="500"
                  placeholder="ms"
                  class="w-20 bg-s1-bg border border-s1-border rounded px-2 py-1 text-xs text-s1-subtle focus:outline-none focus:border-s1-primary"
                />
                <select
                  :value="step.action"
                  @change="onStepActionChange(idx, ($event.target as HTMLSelectElement).value)"
                  class="bg-s1-bg border border-s1-border rounded px-2 py-1 text-xs text-s1-subtle focus:outline-none focus:border-s1-primary"
                >
                  <option value="activity">activity</option>
                  <option value="threat">threat</option>
                  <option value="alert">alert</option>
                  <option value="agent_state">agent_state</option>
                  <option value="mitigate">mitigate</option>
                  <option value="resolve_all_threats">resolve_all_threats</option>
                  <option value="heal_all_agents">heal_all_agents</option>
                </select>
                <button @click="removeStep(idx)" class="p-1 text-s1-muted hover:text-s1-danger transition-colors flex-shrink-0">
                  <X class="w-3.5 h-3.5" />
                </button>
              </div>

              <!-- Action-specific fields -->
              <div class="px-10 pb-3 pt-2 border-t border-s1-border grid grid-cols-2 gap-2">
                <template v-if="step.action === 'activity'">
                  <div>
                    <label class="block text-xs text-s1-muted mb-1">activityType</label>
                    <select v-model.number="step.activityType" class="w-full bg-s1-bg border border-s1-border rounded px-2 py-1 text-xs text-s1-subtle focus:outline-none focus:border-s1-primary">
                      <option :value="2">PROCESS_EVENT (2)</option>
                      <option :value="6">USER_SESSION (6)</option>
                      <option :value="10">ADMIN_NOTE (10)</option>
                      <option :value="80">AGENT_CONNECTED (80)</option>
                      <option :value="120">POLICY_UPDATED (120)</option>
                      <option :value="128">EXCLUSION_ADDED (128)</option>
                      <option :value="1109">NETWORK_ISOLATED (1109)</option>
                      <option :value="2001">DV_QUERY (2001)</option>
                      <option :value="3010">POLICY_EVALUATED (3010)</option>
                      <option :value="3011">POLICY_DETECT_ONLY (3011)</option>
                    </select>
                  </div>
                  <div class="col-span-2">
                    <label class="block text-xs text-s1-muted mb-1">description <span class="text-s1-border">(supports {agentName})</span></label>
                    <input v-model="step.description" class="w-full bg-s1-bg border border-s1-border rounded px-2 py-1 text-xs text-s1-subtle focus:outline-none focus:border-s1-primary" />
                  </div>
                </template>

                <template v-else-if="step.action === 'threat'">
                  <div>
                    <label class="block text-xs text-s1-muted mb-1">threatName</label>
                    <input v-model="step.threatName" class="w-full bg-s1-bg border border-s1-border rounded px-2 py-1 text-xs text-s1-subtle focus:outline-none focus:border-s1-primary" />
                  </div>
                  <div>
                    <label class="block text-xs text-s1-muted mb-1">fileName</label>
                    <input v-model="step.fileName" class="w-full bg-s1-bg border border-s1-border rounded px-2 py-1 text-xs text-s1-subtle focus:outline-none focus:border-s1-primary" />
                  </div>
                  <div>
                    <label class="block text-xs text-s1-muted mb-1">classification</label>
                    <select v-model="step.classification" class="w-full bg-s1-bg border border-s1-border rounded px-2 py-1 text-xs text-s1-subtle focus:outline-none focus:border-s1-primary">
                      <option>Trojan</option><option>Ransomware</option><option>PUA</option><option>Malware</option>
                    </select>
                  </div>
                  <div>
                    <label class="block text-xs text-s1-muted mb-1">confidenceLevel</label>
                    <select v-model="step.confidenceLevel" class="w-full bg-s1-bg border border-s1-border rounded px-2 py-1 text-xs text-s1-subtle focus:outline-none focus:border-s1-primary">
                      <option>malicious</option><option>suspicious</option>
                    </select>
                  </div>
                  <div>
                    <label class="block text-xs text-s1-muted mb-1">mitreTactic</label>
                    <input v-model="step.mitreTactic" class="w-full bg-s1-bg border border-s1-border rounded px-2 py-1 text-xs text-s1-subtle focus:outline-none focus:border-s1-primary" />
                  </div>
                  <div>
                    <label class="block text-xs text-s1-muted mb-1">mitreTechnique</label>
                    <input v-model="step.mitreTechnique" placeholder="T1566.001" class="w-full bg-s1-bg border border-s1-border rounded px-2 py-1 text-xs text-s1-subtle focus:outline-none focus:border-s1-primary" />
                  </div>
                </template>

                <template v-else-if="step.action === 'alert'">
                  <div>
                    <label class="block text-xs text-s1-muted mb-1">severity</label>
                    <select v-model="step.severity" class="w-full bg-s1-bg border border-s1-border rounded px-2 py-1 text-xs text-s1-subtle focus:outline-none focus:border-s1-primary">
                      <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
                    </select>
                  </div>
                  <div>
                    <label class="block text-xs text-s1-muted mb-1">category</label>
                    <input v-model="step.category" class="w-full bg-s1-bg border border-s1-border rounded px-2 py-1 text-xs text-s1-subtle focus:outline-none focus:border-s1-primary" />
                  </div>
                  <div>
                    <label class="block text-xs text-s1-muted mb-1">mitreTactic</label>
                    <input v-model="step.mitreTactic" class="w-full bg-s1-bg border border-s1-border rounded px-2 py-1 text-xs text-s1-subtle focus:outline-none focus:border-s1-primary" />
                  </div>
                  <div>
                    <label class="block text-xs text-s1-muted mb-1">mitreTechnique</label>
                    <input v-model="step.mitreTechnique" class="w-full bg-s1-bg border border-s1-border rounded px-2 py-1 text-xs text-s1-subtle focus:outline-none focus:border-s1-primary" />
                  </div>
                  <div class="col-span-2">
                    <label class="block text-xs text-s1-muted mb-1">description <span class="text-s1-border">(supports {agentName})</span></label>
                    <input v-model="step.description" class="w-full bg-s1-bg border border-s1-border rounded px-2 py-1 text-xs text-s1-subtle focus:outline-none focus:border-s1-primary" />
                  </div>
                </template>

                <template v-else-if="step.action === 'agent_state'">
                  <div>
                    <label class="block text-xs text-s1-muted mb-1">infected</label>
                    <select v-model="step.infected" class="w-full bg-s1-bg border border-s1-border rounded px-2 py-1 text-xs text-s1-subtle focus:outline-none focus:border-s1-primary">
                      <option :value="true">true</option>
                      <option :value="false">false</option>
                    </select>
                  </div>
                  <div>
                    <label class="block text-xs text-s1-muted mb-1">activeThreats</label>
                    <input v-model.number="step.activeThreats" type="number" min="0" class="w-full bg-s1-bg border border-s1-border rounded px-2 py-1 text-xs text-s1-subtle focus:outline-none focus:border-s1-primary" />
                  </div>
                  <div>
                    <label class="block text-xs text-s1-muted mb-1">networkStatus</label>
                    <select v-model="step.networkStatus" class="w-full bg-s1-bg border border-s1-border rounded px-2 py-1 text-xs text-s1-subtle focus:outline-none focus:border-s1-primary">
                      <option>connected</option><option>disconnected</option>
                    </select>
                  </div>
                </template>

                <template v-else>
                  <p class="col-span-2 text-xs text-s1-muted italic">No parameters for this action.</p>
                </template>
              </div>
            </div>

            <div v-if="!editing.steps.length" class="py-8 text-center text-sm text-s1-muted border border-dashed border-s1-border rounded-lg">
              No steps yet — click "Add Step" to begin
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ── Right: Run View ─────────────────────────────────────────────────── -->
    <div v-else class="flex-1 flex flex-col overflow-hidden">
      <div class="p-6 border-b border-s1-border flex items-center justify-between">
        <div>
          <h1 class="text-xl font-semibold text-s1-text">
            {{ selected ? selected.title : 'Select a Playbook' }}
          </h1>
          <p class="text-sm text-s1-muted mt-1">
            {{ selected ? selected.description : 'Choose a simulation from the library' }}
          </p>
        </div>
        <div v-if="selected" class="flex items-center gap-3">
          <select
            v-model="selectedAgentId"
            class="bg-s1-bg border border-s1-border rounded-lg px-3 py-2 text-sm text-s1-text focus:outline-none focus:border-s1-primary focus:ring-1 focus:ring-s1-primary"
          >
            <option v-for="a in agents" :key="a.id" :value="a.id">{{ a.computerName }}</option>
          </select>
          <button
            v-if="!isRunning"
            @click="runPlaybook"
            :disabled="loading || !selectedAgentId"
            class="flex items-center gap-2 px-4 py-2 bg-s1-accent hover:bg-s1-primary disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors"
          >
            <Play class="w-4 h-4" /> Run Playbook
          </button>
          <button
            v-else
            @click="cancelRun"
            class="flex items-center gap-2 px-4 py-2 bg-s1-danger hover:bg-s1-danger/80 text-white rounded-lg text-sm font-medium transition-colors"
          >
            <Square class="w-4 h-4" /> Cancel
          </button>
        </div>
      </div>

      <div class="flex-1 overflow-hidden flex">
        <div class="flex-1 overflow-y-auto p-6">
          <div v-if="!selected" class="flex flex-col items-center justify-center h-full text-center">
            <Activity class="w-12 h-12 text-s1-border mb-4" />
            <p class="text-s1-muted">Select a playbook to see its steps</p>
          </div>

          <div v-else-if="detail" class="space-y-2">
            <h3 class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-4">Timeline Steps</h3>
            <div
              v-for="(step, idx) in detail.steps"
              :key="step.stepId"
              class="flex items-start gap-4 p-3 rounded-lg bg-s1-card border border-s1-border"
            >
              <div
                class="flex-shrink-0 w-7 h-7 rounded-full border flex items-center justify-center text-xs font-bold"
                :class="runStatus.steps?.[idx]?.status === 'done' ? 'bg-green-500/20 border-green-500/40 text-green-400'
                       : runStatus.steps?.[idx]?.status === 'running' ? 'bg-blue-500/20 border-blue-500/40 text-blue-400 animate-pulse'
                       : runStatus.steps?.[idx]?.status === 'error' ? 'bg-red-500/20 border-red-500/40 text-red-400'
                       : 'bg-s1-bg border-s1-border text-s1-muted'"
              >
                <span v-if="runStatus.steps?.[idx]?.status === 'done'">✓</span>
                <span v-else-if="runStatus.steps?.[idx]?.status === 'running'">◐</span>
                <span v-else-if="runStatus.steps?.[idx]?.status === 'error'">✗</span>
                <span v-else>{{ idx + 1 }}</span>
              </div>
              <div class="flex-1 min-w-0">
                <div class="flex items-center gap-2">
                  <span class="text-sm font-medium text-s1-text">{{ step.label }}</span>
                  <span class="text-xs text-s1-muted font-mono">{{ formatDelay(step.delayMs) }}</span>
                </div>
                <div class="text-xs text-s1-muted mt-0.5">{{ step.action }}</div>
              </div>
              <div v-if="runStatus.steps?.[idx]?.completedAt" class="text-xs text-s1-muted flex-shrink-0">
                {{ elapsedSeconds(runStatus.steps![idx].startedAt) }}
              </div>
            </div>
          </div>
        </div>

        <!-- Run status panel -->
        <div
          v-if="runStatus.status !== 'idle' && runStatus.playbookId === selected?.id"
          class="w-72 border-l border-s1-border p-5 flex flex-col gap-4"
        >
          <h3 class="text-xs font-semibold text-s1-muted uppercase tracking-wider">Execution</h3>
          <div class="flex items-center gap-2">
            <span :class="[
              'text-xs px-2 py-1 rounded-full font-medium',
              runStatus.status === 'running' ? 'bg-blue-500/20 text-blue-400' :
              runStatus.status === 'done' ? 'bg-green-500/20 text-green-400' :
              runStatus.status === 'cancelled' ? 'bg-yellow-500/20 text-yellow-400' :
              'bg-red-500/20 text-red-400'
            ]">{{ runStatus.status.toUpperCase() }}</span>
            <span v-if="isRunning" class="text-xs text-s1-muted">
              Step {{ (runStatus.currentStep ?? 0) + 1 }} / {{ runStatus.totalSteps }}
            </span>
          </div>

          <div class="space-y-1">
            <div class="h-1.5 bg-s1-bg rounded-full overflow-hidden">
              <div
                class="h-full bg-blue-500 rounded-full transition-all duration-500"
                :class="{ 'animate-pulse': isRunning }"
                :style="{ width: `${progress}%` }"
              />
            </div>
            <div class="flex justify-between text-xs text-s1-muted">
              <span>{{ progress }}%</span>
              <span v-if="runStatus.startedAt">{{ elapsedSeconds(runStatus.startedAt) }}</span>
            </div>
          </div>

          <div class="space-y-1.5">
            <div v-for="step in runStatus.steps" :key="step.stepId" class="flex items-center gap-2 text-xs">
              <span :class="stepStatusColor(step.status)" class="font-mono w-3 text-center flex-shrink-0">
                {{ stepStatusIcon(step.status) }}
              </span>
              <span :class="step.status === 'done' ? 'text-s1-muted' : step.status === 'running' ? 'text-s1-text' : 'text-s1-muted'">
                {{ step.stepId }}
              </span>
            </div>
          </div>

          <div v-if="runStatus.status === 'done'" class="flex items-center gap-2 text-green-400 text-sm">
            <CheckCircle class="w-4 h-4" /> Playbook complete
          </div>
        </div>
      </div>
    </div>

  </div>
</template>
