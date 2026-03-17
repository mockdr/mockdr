<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import type { Component } from 'vue'
import { ArrowLeft, Wifi, WifiOff, Scan, MessageSquare, Key, Power, Trash2, RefreshCw, Building2, FolderTree, Tag, X, Plus } from 'lucide-vue-next'
import { agentsApi } from '../api/agents'
import { threatsApi } from '../api/threats'
import { sitesApi, groupsApi } from '../api/misc'
import { tagsApi } from '../api/tags'
import StatusBadge from '../components/shared/StatusBadge.vue'
import OsIcon from '../components/shared/OsIcon.vue'
import LoadingSkeleton from '../components/shared/LoadingSkeleton.vue'
import type { Agent, ThreatRecord, InstalledApp, AgentProcess, Site, Group, TagDefinition } from '../types'

const route = useRoute()
const router = useRouter()

const id = route.params['id'] as string

const agent = ref<Agent | null>(null)
const threats = ref<ThreatRecord[]>([])
const apps = ref<InstalledApp[]>([])
const processes = ref<AgentProcess[]>([])
const passphrase = ref<string | null>(null)
const activeTab = ref('overview')
const loading = ref(true)
const actionLoading = ref(false)

onMounted(async () => {
  try {
    const [agentRes, threatsRes] = await Promise.all([
      agentsApi.get(id),
      threatsApi.list({ agentIds: id, limit: 25 }),
    ])
    agent.value = agentRes.data
    threats.value = threatsRes.data
  } finally {
    loading.value = false
  }
})

async function loadApps(): Promise<void> {
  if (apps.value.length) return
  try {
    const res = await agentsApi.applications(id, { limit: 50 })
    apps.value = res.data
  } catch {
    // silently handle — apps tab will remain empty
  }
}

async function loadProcesses(): Promise<void> {
  if (processes.value.length) return
  try {
    const res = await agentsApi.processes(id, { limit: 50 })
    processes.value = res.data
  } catch {
    // silently handle — processes tab will remain empty
  }
}

async function switchTab(tab: string): Promise<void> {
  activeTab.value = tab
  if (tab === 'apps') await loadApps()
  if (tab === 'processes') await loadProcesses()
  if (tab === 'actions') await loadActionData()
}

async function doAction(action: string): Promise<void> {
  actionLoading.value = true
  try {
    await agentsApi.action(action, { filter: { ids: [id] } })
    const res = await agentsApi.get(id)
    agent.value = res.data
  } finally {
    actionLoading.value = false
  }
}

async function showPassphrase(): Promise<void> {
  try {
    const res = await agentsApi.passphrase(id)
    passphrase.value = res.data.passphrase
  } catch {
    passphrase.value = '(failed to retrieve passphrase)'
  }
}

// ── Action-tab data ────────────────────────────────────────────────────────
const sites = ref<Site[]>([])
const groups = ref<Group[]>([])
const selectedSiteId = ref('')
const selectedGroupId = ref('')
const selectedTagId = ref('')
const tagDefs = ref<TagDefinition[]>([])
const actionDataLoaded = ref(false)

async function loadActionData(): Promise<void> {
  if (actionDataLoaded.value) return
  const [sitesRes, groupsRes, tagsRes] = await Promise.all([
    sitesApi.list({ limit: 200 }),
    groupsApi.list({ limit: 200 }),
    tagsApi.list({ includeChildren: true, includeParents: true, limit: 200 }),
  ])
  sites.value = sitesRes.data.sites
  groups.value = groupsRes.data
  tagDefs.value = tagsRes.data
  selectedSiteId.value = agent.value?.siteId ?? ''
  selectedGroupId.value = agent.value?.groupId ?? ''
  actionDataLoaded.value = true
}

async function doMoveToSite(): Promise<void> {
  if (!selectedSiteId.value) return
  actionLoading.value = true
  try {
    await agentsApi.action('move-to-site', {
      filter: { ids: [id] },
      data: { targetSiteId: selectedSiteId.value },
    })
    const res = await agentsApi.get(id)
    agent.value = res.data
  } finally {
    actionLoading.value = false
  }
}

async function doMoveToGroup(): Promise<void> {
  if (!selectedGroupId.value) return
  actionLoading.value = true
  try {
    await agentsApi.action('move-to-group', {
      filter: { ids: [id] },
      data: { targetGroupId: selectedGroupId.value },
    })
    const res = await agentsApi.get(id)
    agent.value = res.data
  } finally {
    actionLoading.value = false
  }
}

const availableTags = computed(() => {
  const assignedIds = new Set(s1Tags.value.map(t => t.id))
  return tagDefs.value.filter(t => !assignedIds.has(t.id))
})

async function addTag(): Promise<void> {
  if (!selectedTagId.value) return
  actionLoading.value = true
  try {
    await agentsApi.action('manage-tags', {
      filter: { ids: [id] },
      data: [{ tagId: selectedTagId.value, operation: 'add' }],
    })
    selectedTagId.value = ''
    const res = await agentsApi.get(id)
    agent.value = res.data
  } finally {
    actionLoading.value = false
  }
}

async function removeTag(tagId: string): Promise<void> {
  actionLoading.value = true
  try {
    await agentsApi.action('manage-tags', {
      filter: { ids: [id] },
      data: [{ tagId, operation: 'remove' }],
    })
    const res = await agentsApi.get(id)
    agent.value = res.data
  } finally {
    actionLoading.value = false
  }
}

const s1Tags = computed(() => agent.value?.tags?.sentinelone ?? [])
const hasAd = computed(() => !!agent.value?.activeDirectory?.computerDistinguishedName)

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'network', label: 'Network' },
  { id: 'ad', label: 'Active Directory' },
  { id: 'threats', label: 'Threats' },
  { id: 'apps', label: 'Installed Apps' },
  { id: 'processes', label: 'Processes' },
  { id: 'actions', label: 'Actions' },
]

interface ActionItem { id: string; label: string; icon: Component; color: string }

const ACTIONS: ActionItem[] = [
  { id: 'connect', label: 'Reconnect', icon: Wifi, color: 'text-s1-success' },
  { id: 'disconnect', label: 'Isolate', icon: WifiOff, color: 'text-s1-danger' },
  { id: 'initiate-scan', label: 'Start Scan', icon: Scan, color: 'text-s1-primary' },
  { id: 'abort-scan', label: 'Abort Scan', icon: RefreshCw, color: 'text-s1-warning' },
  { id: 'shutdown', label: 'Shutdown', icon: Power, color: 'text-s1-warning' },
  { id: 'fetch-logs', label: 'Fetch Logs', icon: MessageSquare, color: 'text-s1-cyan' },
  { id: 'uninstall', label: 'Uninstall', icon: Trash2, color: 'text-s1-danger' },
]
</script>

<template>
  <div>
    <!-- Back -->
    <button @click="router.push('/endpoints')" class="btn-ghost flex items-center gap-2 mb-4 -ml-2">
      <ArrowLeft class="w-4 h-4" /> Endpoints
    </button>

    <div v-if="loading" class="card p-6"><LoadingSkeleton :rows="8" /></div>

    <div v-else-if="agent" class="grid grid-cols-3 gap-4">
      <!-- Left: Agent card -->
      <div class="card p-5 space-y-4">
        <div class="flex items-start gap-3">
          <div class="w-12 h-12 rounded-xl bg-s1-border flex items-center justify-center text-2xl">
            <OsIcon :os-type="agent.osType" />
          </div>
          <div class="flex-1 min-w-0">
            <h2 class="text-lg font-bold text-s1-text truncate">{{ agent.computerName }}</h2>
            <div class="flex items-center gap-2 mt-1">
              <StatusBadge :status="agent.networkStatus" type="agent" />
              <span v-if="agent.infected" class="text-xs text-s1-danger font-medium">⚠ Infected</span>
            </div>
          </div>
        </div>

        <div class="space-y-2 text-sm">
          <div v-for="[k, v] in [
            ['OS', agent.osName],
            ['OS Rev', agent.osRevision],
            ['Agent', agent.agentVersion],
            ['Machine', agent.machineType],
            ['Model', agent.modelName],
            ['Local IP', agent.lastIpToMgmt],
            ['External IP', agent.externalIp],
            ['Domain', agent.domain],
            ['Group', agent.groupName],
            ['Site', agent.siteName],
            ['Mitigation', agent.mitigationMode],
            ['Scan', agent.scanStatus],
          ]" :key="(k as string)" class="flex justify-between gap-2">
            <span class="text-s1-muted">{{ k }}</span>
            <span class="text-s1-text text-right truncate max-w-[60%]">{{ v }}</span>
          </div>

          <!-- Tags -->
          <div v-if="s1Tags.length" class="pt-2">
            <div class="text-s1-muted text-xs mb-1.5">Tags</div>
            <div class="flex flex-wrap gap-1">
              <span v-for="tag in s1Tags" :key="tag.id"
                class="text-xs px-2 py-0.5 rounded-full bg-s1-primary/20 text-s1-primary font-medium">
                {{ tag.key }}
              </span>
            </div>
          </div>

          <div v-if="passphrase" class="mt-3 p-2 bg-s1-bg rounded border border-s1-border">
            <div class="text-xs text-s1-muted mb-1">Passphrase</div>
            <code class="text-s1-warning font-mono text-sm">{{ passphrase }}</code>
          </div>
        </div>

        <button @click="showPassphrase" class="btn-ghost w-full flex items-center justify-center gap-2 text-xs">
          <Key class="w-3.5 h-3.5" /> Show Passphrase
        </button>
      </div>

      <!-- Right: Tabs -->
      <div class="col-span-2 card overflow-hidden">
        <!-- Tab nav -->
        <div class="flex border-b border-s1-border overflow-x-auto">
          <button
            v-for="tab in TABS" :key="tab.id"
            @click="switchTab(tab.id)"
            class="px-4 py-3 text-sm font-medium transition-colors border-b-2 -mb-px whitespace-nowrap"
            :class="activeTab === tab.id
              ? 'text-s1-primary border-s1-primary'
              : 'text-s1-muted border-transparent hover:text-s1-text'"
          >
            {{ tab.label }}
            <span v-if="tab.id === 'threats' && threats.length"
              class="ml-1.5 bg-s1-danger/20 text-s1-danger text-xs px-1.5 rounded-full">
              {{ threats.length }}
            </span>
          </button>
        </div>

        <div class="p-5 overflow-y-auto max-h-[70vh]">

          <!-- Overview -->
          <div v-if="activeTab === 'overview'" class="space-y-5">
            <!-- Hardware -->
            <div>
              <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-2">Hardware</div>
              <div class="grid grid-cols-2 gap-x-6 gap-y-0 text-sm">
                <div v-for="[k, v] in [
                  ['CPU', agent.cpuId],
                  ['CPU Sockets', agent.cpuCount],
                  ['CPU Cores', agent.coreCount],
                  ['Total Memory', agent.totalMemory ? `${agent.totalMemory} MB` : '—'],
                  ['Machine SID', agent.machineSid],
                  ['Serial / UUID', agent.uuid],
                ]" :key="(k as string)" class="flex justify-between py-1.5 border-b border-s1-border/50">
                  <span class="text-s1-muted shrink-0">{{ k }}</span>
                  <span class="text-s1-text font-mono text-xs truncate max-w-[55%] text-right">{{ v ?? '—' }}</span>
                </div>
              </div>
            </div>

            <!-- Agent -->
            <div>
              <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-2">Agent</div>
              <div class="grid grid-cols-2 gap-x-6 gap-y-0 text-sm">
                <div v-for="[k, v] in [
                  ['Registered', agent.registeredAt?.slice(0, 10)],
                  ['Last Active', agent.lastActiveDate?.slice(0, 10)],
                  ['Last User', agent.lastLoggedInUserName],
                  ['Installer', agent.installerType],
                  ['Ranger', agent.rangerStatus],
                  ['Ranger Ver.', agent.rangerVersion],
                  ['Detection', agent.detectionState],
                  ['Active Threats', agent.activeThreats],
                  ['Firewall', agent.firewallEnabled ? 'Enabled' : 'Disabled'],
                  ['Up to Date', agent.isUpToDate ? 'Yes' : 'No'],
                  ['Allow Remote Shell', agent.allowRemoteShell ? 'Yes' : 'No'],
                  ['Vuln. Status', agent.appsVulnerabilityStatus],
                  ['First Full Mode', agent.firstFullModeTime?.slice(0, 10) ?? '—'],
                  ['Scan Finished', agent.scanFinishedAt?.slice(0, 10) ?? '—'],
                ]" :key="(k as string)" class="flex justify-between py-1.5 border-b border-s1-border/50">
                  <span class="text-s1-muted shrink-0">{{ k }}</span>
                  <span class="text-s1-text font-mono text-xs truncate max-w-[55%] text-right">{{ v ?? '—' }}</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Network -->
          <div v-else-if="activeTab === 'network'" class="space-y-4 text-sm">
            <div v-if="!agent.networkInterfaces?.length" class="text-s1-muted text-center py-8">No interface data</div>
            <div v-else v-for="iface in agent.networkInterfaces" :key="iface.id"
              class="rounded-lg border border-s1-border p-4 space-y-2">
              <div class="font-semibold text-s1-text flex items-center gap-2">
                <Wifi class="w-4 h-4 text-s1-primary" />
                {{ iface.name }}
              </div>
              <div class="grid grid-cols-2 gap-x-6 gap-y-0">
                <div v-for="[k, v] in [
                  ['IPv4', iface.inet?.join(', ')],
                  ['IPv6', iface.inet6?.join(', ')],
                  ['MAC', iface.physical],
                  ['Gateway IP', iface.gatewayIp],
                  ['Gateway MAC', iface.gatewayMacAddress],
                  ['Group IP Range', agent.groupIp],
                  ['External IP', agent.externalIp],
                  ['Network Status', agent.networkStatus],
                  ['Quarantine', agent.networkQuarantineEnabled ? 'Enabled' : 'Disabled'],
                  ['Location Type', agent.locationType],
                  ['Proxy (Console)', agent.proxyStates?.console ? 'Yes' : 'No'],
                  ['Proxy (DV)', agent.proxyStates?.deepVisibility ? 'Yes' : 'No'],
                ]" :key="(k as string)" class="flex justify-between py-1.5 border-b border-s1-border/50">
                  <span class="text-s1-muted shrink-0">{{ k }}</span>
                  <span class="text-s1-text font-mono text-xs truncate max-w-[55%] text-right">{{ v ?? '—' }}</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Active Directory -->
          <div v-else-if="activeTab === 'ad'" class="space-y-5 text-sm">
            <div v-if="!hasAd" class="text-s1-muted text-center py-8">No Active Directory data (non-Windows or not domain-joined)</div>
            <div v-else>
              <!-- Identity -->
              <div>
                <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-2">Identity</div>
                <div class="space-y-1.5">
                  <div v-for="[k, v] in [
                    ['Computer DN', agent.activeDirectory!.computerDistinguishedName],
                    ['Last User DN', agent.activeDirectory!.lastUserDistinguishedName],
                    ['UPN', agent.activeDirectory!.userPrincipalName],
                  ]" :key="(k as string)" class="flex flex-col gap-0.5 py-1.5 border-b border-s1-border/50">
                    <span class="text-s1-muted text-xs">{{ k }}</span>
                    <span class="text-s1-text font-mono text-xs break-all">{{ v }}</span>
                  </div>
                </div>
              </div>

              <!-- Computer group memberships -->
              <div>
                <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-2">
                  Computer Group Memberships ({{ agent.activeDirectory!.computerMemberOf?.length ?? 0 }})
                </div>
                <div class="space-y-1">
                  <div v-for="dn in agent.activeDirectory!.computerMemberOf" :key="dn"
                    class="text-xs font-mono text-s1-text bg-s1-bg rounded px-2 py-1 break-all">
                    {{ dn }}
                  </div>
                </div>
              </div>

              <!-- User group memberships -->
              <div>
                <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-2">
                  Last User Group Memberships ({{ agent.activeDirectory!.lastUserMemberOf?.length ?? 0 }})
                </div>
                <div class="space-y-1">
                  <div v-for="dn in agent.activeDirectory!.lastUserMemberOf" :key="dn"
                    class="text-xs font-mono text-s1-text bg-s1-bg rounded px-2 py-1 break-all">
                    {{ dn }}
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- Threats -->
          <div v-else-if="activeTab === 'threats'">
            <div v-if="!threats.length" class="text-center py-8 text-s1-muted text-sm">🎉 No threats on this endpoint</div>
            <div v-else class="space-y-2">
              <div v-for="t in threats" :key="t.id"
                class="flex items-center justify-between p-3 rounded-lg bg-s1-bg hover:bg-s1-hover cursor-pointer"
                @click="router.push(`/threats/${t.id}`)">
                <div>
                  <div class="font-medium text-s1-text text-sm">{{ t.threatInfo.threatName }}</div>
                  <div class="text-xs text-s1-muted">{{ t.threatInfo.classification }} · {{ t.threatInfo.fileName }}</div>
                </div>
                <StatusBadge :status="t.threatInfo.mitigationStatus" type="threat" />
              </div>
            </div>
          </div>

          <!-- Apps -->
          <div v-else-if="activeTab === 'apps'">
            <div v-if="!apps.length" class="text-center py-8 text-s1-muted text-sm">No application data</div>
            <div v-else class="space-y-1.5">
              <div v-for="app in apps" :key="app.id"
                class="flex items-center justify-between p-2.5 rounded bg-s1-bg text-sm">
                <div>
                  <span class="text-s1-text">{{ app.name }}</span>
                  <span class="text-s1-muted ml-2 text-xs">{{ app.version }}</span>
                </div>
                <span class="text-xs text-s1-muted">{{ app.vendor }}</span>
              </div>
            </div>
          </div>

          <!-- Processes -->
          <div v-else-if="activeTab === 'processes'">
            <div class="space-y-1">
              <div v-for="p in processes" :key="p.pid"
                class="flex items-center justify-between p-2.5 rounded bg-s1-bg text-sm font-mono">
                <span class="text-s1-text">{{ p.name }}</span>
                <div class="flex gap-4 text-xs text-s1-muted">
                  <span>PID {{ p.pid }}</span>
                  <span>{{ p.cpuUsage }}% CPU</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Actions -->
          <div v-else-if="activeTab === 'actions'" class="space-y-6">

            <!-- Quick actions -->
            <div>
              <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-3">Quick Actions</div>
              <div class="grid grid-cols-3 gap-3">
                <button
                  v-for="act in ACTIONS" :key="act.id"
                  @click="doAction(act.id)"
                  :disabled="actionLoading"
                  class="flex flex-col items-center gap-2 p-4 rounded-xl bg-s1-bg hover:bg-s1-hover transition-colors disabled:opacity-50"
                >
                  <component :is="act.icon" class="w-5 h-5" :class="act.color" />
                  <span class="text-xs font-medium text-s1-text">{{ act.label }}</span>
                </button>
              </div>
            </div>

            <!-- Move to Site -->
            <div>
              <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-3 flex items-center gap-1.5">
                <Building2 class="w-3.5 h-3.5" /> Move to Site
              </div>
              <div class="flex gap-2">
                <select
                  v-model="selectedSiteId"
                  class="input flex-1 text-sm"
                  :disabled="actionLoading"
                >
                  <option v-for="s in sites" :key="s.id" :value="s.id">{{ s.name }}</option>
                </select>
                <button
                  @click="doMoveToSite"
                  :disabled="actionLoading || !selectedSiteId"
                  class="btn-primary px-4 text-sm"
                >
                  Move
                </button>
              </div>
              <p class="text-xs text-s1-muted mt-1">Current: <span class="text-s1-text">{{ agent.siteName }}</span></p>
            </div>

            <!-- Move to Group -->
            <div>
              <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-3 flex items-center gap-1.5">
                <FolderTree class="w-3.5 h-3.5" /> Move to Group
              </div>
              <div class="flex gap-2">
                <select
                  v-model="selectedGroupId"
                  class="input flex-1 text-sm"
                  :disabled="actionLoading"
                >
                  <option v-for="g in groups" :key="g.id" :value="g.id">{{ g.name }}</option>
                </select>
                <button
                  @click="doMoveToGroup"
                  :disabled="actionLoading || !selectedGroupId"
                  class="btn-primary px-4 text-sm"
                >
                  Move
                </button>
              </div>
              <p class="text-xs text-s1-muted mt-1">Current: <span class="text-s1-text">{{ agent.groupName }}</span></p>
            </div>

            <!-- Manage Tags -->
            <div>
              <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-3 flex items-center gap-1.5">
                <Tag class="w-3.5 h-3.5" /> Tags
              </div>
              <div class="flex flex-wrap gap-1.5 mb-3 min-h-[28px]">
                <span v-if="!s1Tags.length" class="text-xs text-s1-muted">No tags assigned</span>
                <span
                  v-for="tag in s1Tags" :key="tag.id"
                  class="flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-s1-primary/20 text-s1-primary font-medium"
                >
                  {{ tag.key }}: {{ tag.value }}
                  <button @click="removeTag(tag.id)" :disabled="actionLoading" class="hover:text-s1-danger transition-colors">
                    <X class="w-3 h-3" />
                  </button>
                </span>
              </div>
              <div class="flex gap-2">
                <select
                  v-model="selectedTagId"
                  class="input flex-1 text-sm"
                  :disabled="actionLoading"
                >
                  <option value="" disabled>Select a tag to assign…</option>
                  <option v-for="t in availableTags" :key="t.id" :value="t.id">
                    {{ t.key }}: {{ t.value }} ({{ t.scopeLevel }})
                  </option>
                </select>
                <button
                  @click="addTag"
                  :disabled="actionLoading || !selectedTagId"
                  class="btn-primary px-3"
                >
                  <Plus class="w-4 h-4" />
                </button>
              </div>
            </div>

          </div>

        </div>
      </div>
    </div>
  </div>
</template>
