<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { Pencil, X, Save } from 'lucide-vue-next'
import { sitesApi, groupsApi } from '../api/misc'
import client from '../api/client'
import LoadingSkeleton from '../components/shared/LoadingSkeleton.vue'
import type { Site, Group, Policy } from '../types'

const MITIGATION_MODES = ['protect', 'detect', 'none']

// ── Scope ──────────────────────────────────────────────────────────────────────
type ScopeType = 'site' | 'group'
const scopeType = ref<ScopeType>('site')

// ── Data ───────────────────────────────────────────────────────────────────────
const sites        = ref<Site[]>([])
const selectedSite = ref<Site | null>(null)
const groups       = ref<Group[]>([])
const selectedGroup = ref<Group | null>(null)

const policy  = ref<Policy | null>(null)
const draft   = ref<Policy | null>(null)   // non-null = edit mode
const loading       = ref(true)
const groupsLoading = ref(false)
const policyLoading = ref(false)
const saving        = ref(false)

// ── Init ───────────────────────────────────────────────────────────────────────
onMounted(async () => {
  try {
    const res = await sitesApi.list({ limit: 100 })
    sites.value = res.data.sites
    if (res.data.sites.length) {
      selectedSite.value = res.data.sites[0]
      await loadGroupsForSite()
      await loadPolicy()
    }
  } finally {
    loading.value = false
  }
})

// ── Group loading ──────────────────────────────────────────────────────────────
async function loadGroupsForSite(): Promise<void> {
  if (!selectedSite.value) { groups.value = []; selectedGroup.value = null; return }
  groupsLoading.value = true
  try {
    const res = await groupsApi.list({ siteIds: selectedSite.value.id, limit: 100 })
    groups.value = res.data
    selectedGroup.value = res.data.length ? res.data[0] : null
  } finally {
    groupsLoading.value = false
  }
}

// ── Policy loading / saving ────────────────────────────────────────────────────
async function loadPolicy(): Promise<void> {
  const params = scopeType.value === 'site'
    ? selectedSite.value  ? { siteId:  selectedSite.value.id  } : null
    : selectedGroup.value ? { groupId: selectedGroup.value.id } : null

  if (!params) { policy.value = null; draft.value = null; return }

  policyLoading.value = true
  try {
    const res = await client.get('/policies', { params }) as { data: Policy }
    policy.value = res.data
    draft.value  = null
  } finally {
    policyLoading.value = false
  }
}

async function savePolicy(): Promise<void> {
  if (!draft.value) return
  const params = scopeType.value === 'site'
    ? selectedSite.value  ? { siteId:  selectedSite.value.id  } : null
    : selectedGroup.value ? { groupId: selectedGroup.value.id } : null
  if (!params) return

  saving.value = true
  try {
    await client.put('/policies', draft.value, { params })
    await loadPolicy()
  } finally {
    saving.value = false
  }
}

// ── Scope / selector change handlers ──────────────────────────────────────────
async function onScopeChange(): Promise<void> {
  policy.value = null
  draft.value  = null
  if (scopeType.value === 'group' && selectedSite.value) {
    await loadGroupsForSite()
  }
  await loadPolicy()
}

async function onSiteChange(): Promise<void> {
  policy.value = null
  draft.value  = null
  groups.value = []
  selectedGroup.value = null
  if (scopeType.value === 'group') {
    await loadGroupsForSite()
  }
  await loadPolicy()
}

async function onGroupChange(): Promise<void> {
  policy.value = null
  draft.value  = null
  await loadPolicy()
}

// ── Edit helpers ───────────────────────────────────────────────────────────────
function openEdit(): void {
  if (!policy.value) return
  draft.value = { ...policy.value, engines: { ...policy.value.engines } }
}

function cancelEdit(): void { draft.value = null }

// ── Display helpers ────────────────────────────────────────────────────────────
function boolLabel(val: boolean): string { return val ? 'Enabled' : 'Disabled' }
function boolClass(val: boolean): string  { return val ? 'text-s1-success' : 'text-s1-muted' }
function modeClass(val: string): string {
  return val === 'protect' ? 'text-s1-success' : val === 'detect' ? 'text-yellow-400' : 'text-s1-muted'
}
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-s1-text">Policies</h1>
        <p class="text-s1-muted text-sm">Site and group policy configuration</p>
      </div>

      <div class="flex items-center gap-3">
        <!-- Scope toggle -->
        <div class="flex rounded-lg border border-s1-border overflow-hidden text-sm">
          <button
            @click="scopeType = 'site'; onScopeChange()"
            :class="scopeType === 'site' ? 'bg-s1-primary text-white' : 'text-s1-muted hover:text-s1-text'"
            class="px-3 py-1.5 transition-colors"
          >Site</button>
          <button
            @click="scopeType = 'group'; onScopeChange()"
            :class="scopeType === 'group' ? 'bg-s1-primary text-white' : 'text-s1-muted hover:text-s1-text'"
            class="px-3 py-1.5 transition-colors"
          >Group</button>
        </div>

        <!-- Site selector (always shown) -->
        <select
          v-if="sites.length"
          v-model="selectedSite"
          @change="onSiteChange"
          :disabled="!!draft"
          class="input w-48 text-sm disabled:opacity-50"
        >
          <option v-for="s in sites" :key="s.id" :value="s">{{ s.name }}</option>
        </select>

        <!-- Group selector (shown only in group scope) -->
        <select
          v-if="scopeType === 'group'"
          v-model="selectedGroup"
          @change="onGroupChange"
          :disabled="!!draft || groupsLoading"
          class="input w-48 text-sm disabled:opacity-50"
        >
          <option v-if="!groups.length" :value="null" disabled>No groups</option>
          <option v-for="g in groups" :key="g.id" :value="g">{{ g.name }} ({{ g.id.slice(-6) }})</option>
        </select>

        <!-- Edit / Save / Cancel -->
        <template v-if="policy && !draft">
          <button
            @click="openEdit"
            class="flex items-center gap-1.5 px-3 py-1.5 bg-s1-primary hover:bg-s1-primary/80 text-white rounded-lg text-sm font-medium transition-colors"
          >
            <Pencil class="w-3.5 h-3.5" /> Edit Policy
          </button>
        </template>
        <template v-else-if="draft">
          <button
            @click="cancelEdit"
            class="flex items-center gap-1.5 px-3 py-1.5 border border-s1-border text-s1-muted hover:text-s1-text rounded-lg text-sm transition-colors"
          >
            <X class="w-3.5 h-3.5" /> Cancel
          </button>
          <button
            @click="savePolicy"
            :disabled="saving"
            class="flex items-center gap-1.5 px-3 py-1.5 bg-s1-primary hover:bg-s1-primary/80 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors"
          >
            <Save class="w-3.5 h-3.5" /> {{ saving ? 'Saving…' : 'Save' }}
          </button>
        </template>
      </div>
    </div>

    <div v-if="loading || policyLoading || groupsLoading"><LoadingSkeleton :rows="8" /></div>

    <div v-else-if="policy || draft" class="grid grid-cols-1 lg:grid-cols-2 gap-4">

      <!-- Detection / Mitigation -->
      <div class="card p-5 space-y-3">
        <h2 class="text-sm font-semibold text-s1-text border-b border-s1-border pb-2">Detection</h2>

        <!-- mitigationMode -->
        <div class="flex justify-between items-center py-1.5 border-b border-s1-border/40 text-sm">
          <span class="text-s1-muted">Mitigation Mode</span>
          <select v-if="draft" v-model="draft.mitigationMode" class="input text-xs py-0.5 px-2 w-32">
            <option v-for="m in MITIGATION_MODES" :key="m" :value="m">{{ m }}</option>
          </select>
          <span v-else :class="modeClass(policy!.mitigationMode)" class="font-medium capitalize text-xs">
            {{ policy!.mitigationMode }}
          </span>
        </div>

        <!-- mitigationModeSuspicious -->
        <div class="flex justify-between items-center py-1.5 border-b border-s1-border/40 text-sm">
          <span class="text-s1-muted">Suspicious Mode</span>
          <select v-if="draft" v-model="draft.mitigationModeSuspicious" class="input text-xs py-0.5 px-2 w-32">
            <option v-for="m in MITIGATION_MODES" :key="m" :value="m">{{ m }}</option>
          </select>
          <span v-else :class="modeClass(policy!.mitigationModeSuspicious)" class="font-medium capitalize text-xs">
            {{ policy!.mitigationModeSuspicious }}
          </span>
        </div>

        <!-- Boolean toggles: Detection -->
        <div
          v-for="[label, field] in [
            ['Auto Mitigate', 'autoMitigate' ],
            ['Scan New Agents', 'scanNewAgents'],
            ['Scan on Written', 'scanOnWritten'],
          ]"
          :key="field"
          class="flex justify-between items-center py-1.5 border-b border-s1-border/40 text-sm"
        >
          <span class="text-s1-muted">{{ label }}</span>
          <button
            v-if="draft"
            @click="(draft as any)[field] = !(draft as any)[field]"
            :class="(draft as any)[field]
              ? 'bg-s1-success/20 text-s1-success border-s1-success/30'
              : 'bg-s1-border/20 text-s1-muted border-s1-border'"
            class="text-xs px-2.5 py-0.5 rounded-full border font-medium transition-colors w-20 text-center"
          >{{ (draft as any)[field] ? 'Enabled' : 'Disabled' }}</button>
          <span v-else :class="boolClass((policy as any)[field])" class="font-medium text-xs">
            {{ boolLabel((policy as any)[field]) }}
          </span>
        </div>
      </div>

      <!-- Monitoring & Blocking -->
      <div class="card p-5 space-y-3">
        <h2 class="text-sm font-semibold text-s1-text border-b border-s1-border pb-2">Monitoring & Blocking</h2>
        <div
          v-for="[label, field] in [
            ['Monitor on Write', 'monitorOnWrite' ],
            ['Monitor on Execute', 'monitorOnExecute'],
            ['Block on Write', 'blockOnWrite' ],
            ['Block on Execute', 'blockOnExecute' ],
          ]"
          :key="field"
          class="flex justify-between items-center py-1.5 border-b border-s1-border/40 text-sm"
        >
          <span class="text-s1-muted">{{ label }}</span>
          <button
            v-if="draft"
            @click="(draft as any)[field] = !(draft as any)[field]"
            :class="(draft as any)[field]
              ? 'bg-s1-success/20 text-s1-success border-s1-success/30'
              : 'bg-s1-border/20 text-s1-muted border-s1-border'"
            class="text-xs px-2.5 py-0.5 rounded-full border font-medium transition-colors w-20 text-center"
          >{{ (draft as any)[field] ? 'Enabled' : 'Disabled' }}</button>
          <span v-else :class="boolClass((policy as any)[field])" class="font-medium text-xs">
            {{ boolLabel((policy as any)[field]) }}
          </span>
        </div>
      </div>

      <!-- Detection Engines -->
      <div
        v-if="Object.keys((draft ?? policy)!.engines ?? {}).length"
        class="card p-5 space-y-3 lg:col-span-2"
      >
        <h2 class="text-sm font-semibold text-s1-text border-b border-s1-border pb-2">Detection Engines</h2>
        <div class="grid grid-cols-2 sm:grid-cols-3 gap-3">
          <div
            v-for="[key, val] in Object.entries((draft ?? policy)!.engines ?? {})"
            :key="key"
            class="bg-s1-bg rounded-lg p-3 flex items-center justify-between"
          >
            <span class="text-xs text-s1-muted capitalize">{{ key.replace(/([A-Z])/g, ' $1').trim() }}</span>
            <button
              v-if="draft"
              @click="draft!.engines![key] = !draft!.engines![key]"
              :class="draft!.engines![key]
                ? 'bg-s1-success/20 text-s1-success border-s1-success/30'
                : 'bg-s1-border/20 text-s1-muted border-s1-border'"
              class="text-xs px-2 py-0.5 rounded-full border font-medium transition-colors w-10 text-center"
            >{{ draft!.engines![key] ? 'On' : 'Off' }}</button>
            <span v-else :class="val ? 'text-s1-success' : 'text-s1-muted'" class="text-xs font-medium">
              {{ val ? 'On' : 'Off' }}
            </span>
          </div>
        </div>
      </div>

    </div>

    <div v-else class="card p-12 text-center text-s1-muted text-sm">
      <template v-if="scopeType === 'group' && !groups.length">
        No groups found for this site
      </template>
      <template v-else>
        Select a {{ scopeType }} to view its policy
      </template>
    </div>
  </div>
</template>
