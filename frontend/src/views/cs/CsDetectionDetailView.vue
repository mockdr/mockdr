<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowLeft } from 'lucide-vue-next'
import { ensureCsAuth, csDetectionsApi } from '../../api/crowdstrike'
import type { CsDetection } from '../../types/crowdstrike'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

const route = useRoute()
const router = useRouter()
const id = route.params['id'] as string

const detection = ref<CsDetection | null>(null)
const loading = ref(true)
const activeTab = ref('overview')
const updating = ref(false)

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'behaviors', label: 'Behaviors' },
  { id: 'device', label: 'Device' },
]

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

async function updateStatus(newStatus: string): Promise<void> {
  if (!detection.value) return
  updating.value = true
  try {
    await csDetectionsApi.update([detection.value.composite_id], { status: newStatus })
    // Re-fetch
    const res = await csDetectionsApi.getEntities([detection.value.composite_id])
    if (res.resources.length > 0) detection.value = res.resources[0]
  } finally {
    updating.value = false
  }
}

onMounted(async () => {
  try {
    await ensureCsAuth()
    const res = await csDetectionsApi.getEntities([id])
    if (res.resources.length > 0) {
      detection.value = res.resources[0]
    }
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <!-- Back -->
    <button @click="router.push('/crowdstrike/detections')" class="btn-ghost flex items-center gap-2 mb-4 -ml-2">
      <ArrowLeft class="w-4 h-4" /> CS Detections
    </button>

    <div v-if="loading" class="card p-6"><LoadingSkeleton :rows="8" /></div>

    <div v-else-if="detection" class="grid grid-cols-3 gap-4">
      <!-- Left: Detection summary card -->
      <div class="card p-5 space-y-4">
        <div>
          <h2 class="text-lg font-bold text-s1-text truncate">Detection</h2>
          <div class="text-xs text-s1-muted font-mono mt-1 break-all">{{ detection.composite_id }}</div>
        </div>

        <div class="flex items-center gap-2">
          <span
            class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
            :class="severityBadgeClass(detection.max_severity)"
          >
            {{ detection.max_severity_displayname }} ({{ detection.max_severity }})
          </span>
          <span
            class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
            :class="statusBadgeClass(detection.status)"
          >
            {{ detection.status }}
          </span>
        </div>

        <div class="space-y-2 text-sm">
          <div v-for="[k, v] in [
            ['Host', detection.device?.hostname],
            ['Platform', detection.device?.platform_name],
            ['Host Status', detection.device?.status],
            ['Confidence', detection.max_confidence],
            ['First Behavior', detection.first_behavior?.slice(0, 19)],
            ['Last Behavior', detection.last_behavior?.slice(0, 19)],
            ['Created', detection.created_timestamp?.slice(0, 19)],
            ['Updated', detection.date_updated?.slice(0, 19)],
            ['Assigned To', detection.assigned_to_name],
          ]" :key="(k as string)" class="flex justify-between gap-2">
            <span class="text-s1-muted">{{ k }}</span>
            <span class="text-s1-text text-right truncate max-w-[60%] font-mono text-xs">{{ v ?? '--' }}</span>
          </div>
        </div>

        <!-- Status update buttons -->
        <div class="pt-2 space-y-2">
          <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider">Update Status</div>
          <div class="grid grid-cols-2 gap-2">
            <button
              v-for="st in ['new', 'in_progress', 'true_positive', 'false_positive', 'closed']" :key="st"
              @click="updateStatus(st)"
              :disabled="updating || detection.status === st"
              class="px-3 py-1.5 rounded text-xs font-medium transition-colors disabled:opacity-30"
              :class="statusBadgeClass(st)"
            >
              {{ st }}
            </button>
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
              ? 'text-red-400 border-red-500'
              : 'text-s1-muted border-transparent hover:text-s1-text'"
          >
            {{ tab.label }}
            <span v-if="tab.id === 'behaviors' && detection.behaviors?.length"
              class="ml-1.5 bg-red-500/20 text-red-400 text-xs px-1.5 rounded-full">
              {{ detection.behaviors.length }}
            </span>
          </button>
        </div>

        <div class="p-5 overflow-y-auto max-h-[70vh]">

          <!-- Overview -->
          <div v-if="activeTab === 'overview'" class="space-y-5">
            <div>
              <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-2">Detection Summary</div>
              <div class="grid grid-cols-2 gap-x-6 gap-y-0 text-sm">
                <div v-for="[k, v] in [
                  ['Composite ID', detection.composite_id],
                  ['Max Severity', `${detection.max_severity_displayname} (${detection.max_severity})`],
                  ['Max Confidence', detection.max_confidence],
                  ['Status', detection.status],
                  ['Created', detection.created_timestamp],
                  ['First Behavior', detection.first_behavior],
                  ['Last Behavior', detection.last_behavior],
                  ['Assigned To', detection.assigned_to_name ?? 'Unassigned'],
                  ['Date Updated', detection.date_updated],
                ]" :key="(k as string)" class="flex justify-between py-1.5 border-b border-s1-border/50">
                  <span class="text-s1-muted shrink-0">{{ k }}</span>
                  <span class="text-s1-text font-mono text-xs truncate max-w-[55%] text-right">{{ v ?? '--' }}</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Behaviors -->
          <div v-else-if="activeTab === 'behaviors'">
            <div v-if="!detection.behaviors?.length" class="text-center py-8 text-s1-muted text-sm">
              No behaviors recorded
            </div>
            <div v-else class="space-y-4">
              <div
                v-for="(b, i) in detection.behaviors" :key="b.behavior_id"
                class="rounded-lg border border-s1-border p-4 space-y-3"
              >
                <div class="flex items-center justify-between">
                  <div class="font-semibold text-s1-text text-sm">Behavior #{{ i + 1 }}</div>
                  <span
                    class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                    :class="severityBadgeClass(b.severity)"
                  >
                    Severity: {{ b.severity }}
                  </span>
                </div>

                <div class="grid grid-cols-2 gap-x-6 gap-y-0 text-sm">
                  <div v-for="[k, v] in [
                    ['Behavior ID', b.behavior_id],
                    ['Filename', b.filename],
                    ['Filepath', b.filepath],
                    ['Scenario', b.scenario],
                    ['Severity', b.severity],
                    ['Confidence', b.confidence],
                    ['Timestamp', b.timestamp?.slice(0, 19)],
                    ['User', b.user_name],
                  ]" :key="(k as string)" class="flex justify-between py-1.5 border-b border-s1-border/50">
                    <span class="text-s1-muted shrink-0">{{ k }}</span>
                    <span class="text-s1-text font-mono text-xs truncate max-w-[55%] text-right">{{ v ?? '--' }}</span>
                  </div>
                </div>

                <!-- MITRE ATT&CK -->
                <div class="bg-s1-bg rounded p-3">
                  <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-2">MITRE ATT&CK</div>
                  <div class="grid grid-cols-2 gap-2 text-sm">
                    <div>
                      <span class="text-s1-muted text-xs">Tactic</span>
                      <div class="text-s1-text text-xs font-mono">{{ b.tactic ?? '--' }} ({{ b.tactic_id ?? '--' }})</div>
                    </div>
                    <div>
                      <span class="text-s1-muted text-xs">Technique</span>
                      <div class="text-s1-text text-xs font-mono">{{ b.technique ?? '--' }} ({{ b.technique_id ?? '--' }})</div>
                    </div>
                  </div>
                </div>

                <!-- Command line -->
                <div v-if="b.cmdline">
                  <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-1">Command Line</div>
                  <pre class="text-xs font-mono text-s1-text bg-s1-bg rounded p-2 overflow-x-auto">{{ b.cmdline }}</pre>
                </div>

                <!-- Hashes -->
                <div v-if="b.sha256 || b.md5">
                  <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-1">File Hashes</div>
                  <div class="text-xs font-mono text-s1-muted space-y-0.5">
                    <div v-if="b.sha256">SHA256: {{ b.sha256 }}</div>
                    <div v-if="b.md5">MD5: {{ b.md5 }}</div>
                  </div>
                </div>

                <!-- IOC -->
                <div v-if="b.ioc_type || b.ioc_value">
                  <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-1">IOC</div>
                  <div class="text-xs font-mono text-s1-muted">
                    {{ b.ioc_type }}: {{ b.ioc_value }}
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- Device -->
          <div v-else-if="activeTab === 'device'" class="space-y-5">
            <div>
              <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-2">Device Information</div>
              <div class="grid grid-cols-2 gap-x-6 gap-y-0 text-sm">
                <div v-for="[k, v] in [
                  ['Device ID', detection.device?.device_id],
                  ['Hostname', detection.device?.hostname],
                  ['Platform', detection.device?.platform_name],
                  ['OS Version', detection.device?.os_version],
                  ['External IP', detection.device?.external_ip],
                  ['Status', detection.device?.status],
                  ['Agent Version', detection.device?.agent_version],
                ]" :key="(k as string)" class="flex justify-between py-1.5 border-b border-s1-border/50">
                  <span class="text-s1-muted shrink-0">{{ k }}</span>
                  <span class="text-s1-text font-mono text-xs truncate max-w-[55%] text-right">{{ v ?? '--' }}</span>
                </div>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>

    <div v-else class="card p-10 text-center">
      <p class="text-s1-muted">Detection not found</p>
      <button @click="router.push('/crowdstrike/detections')" class="btn-ghost mt-4 text-sm">Back to detections</button>
    </div>
  </div>
</template>
