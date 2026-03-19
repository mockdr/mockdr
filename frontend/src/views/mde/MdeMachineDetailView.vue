<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowLeft, Shield, ShieldOff, Search } from 'lucide-vue-next'
import { ensureMdeAuth, mdeMachinesApi, mdeAlertsApi } from '../../api/defender'
import type { MdeMachine, MdeAlert } from '../../types/defender'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

const route = useRoute()
const router = useRouter()
const id = route.params['id'] as string

const machine = ref<MdeMachine | null>(null)
const alerts = ref<MdeAlert[]>([])
const loading = ref(true)
const actionLoading = ref(false)
const activeTab = ref('overview')

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'alerts', label: 'Alerts' },
]

function healthBadgeClass(status: string): string {
  switch (status) {
    case 'Active': return 'bg-green-500/15 text-green-400'
    case 'Inactive': return 'bg-yellow-500/15 text-yellow-400'
    case 'ImpairedCommunication': return 'bg-red-500/15 text-red-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function severityBadgeClass(severity: string): string {
  switch (severity) {
    case 'High': return 'bg-red-500/15 text-red-400'
    case 'Medium': return 'bg-orange-500/15 text-orange-400'
    case 'Low': return 'bg-yellow-500/15 text-yellow-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function performAction(action: 'isolate' | 'unisolate' | 'quickScan' | 'fullScan'): Promise<void> {
  if (!machine.value) return
  actionLoading.value = true
  try {
    if (action === 'isolate') {
      await mdeMachinesApi.isolate(id, 'Isolated from detail view')
    } else if (action === 'unisolate') {
      await mdeMachinesApi.unisolate(id, 'Released from detail view')
    } else {
      await mdeMachinesApi.scanAction(id, action === 'quickScan' ? 'Quick' : 'Full')
    }
    // Refresh
    const res = await mdeMachinesApi.get(id)
    machine.value = res
  } finally {
    actionLoading.value = false
  }
}

onMounted(async () => {
  try {
    await ensureMdeAuth()
    const [machineRes, alertsRes] = await Promise.all([
      mdeMachinesApi.get(id),
      mdeAlertsApi.list({ $filter: `machineId eq '${id}'`, $top: 50 }),
    ])
    machine.value = machineRes
    alerts.value = alertsRes.value ?? []
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <!-- Back -->
    <button @click="router.push('/defender/machines')" class="btn-ghost flex items-center gap-2 mb-4 -ml-2">
      <ArrowLeft class="w-4 h-4" /> MDE Machines
    </button>

    <div v-if="loading" class="card p-6"><LoadingSkeleton :rows="8" /></div>

    <div v-else-if="machine" class="grid grid-cols-3 gap-4">
      <!-- Left: Machine card -->
      <div class="card p-5 space-y-4">
        <div class="flex items-start gap-3">
          <div class="w-12 h-12 rounded-xl flex items-center justify-center text-lg font-bold bg-green-500/20 text-green-400">
            {{ machine.osPlatform?.charAt(0) ?? '?' }}
          </div>
          <div class="flex-1 min-w-0">
            <h2 class="text-lg font-bold text-s1-text truncate">{{ machine.computerDnsName }}</h2>
            <div class="flex items-center gap-2 mt-1">
              <span
                class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                :class="healthBadgeClass(machine.healthStatus)"
              >
                {{ machine.healthStatus }}
              </span>
              <span class="text-xs text-s1-muted">{{ machine.osPlatform }}</span>
            </div>
          </div>
        </div>

        <!-- Actions -->
        <div class="flex flex-wrap gap-2">
          <button @click="performAction('isolate')" :disabled="actionLoading" class="btn-ghost flex items-center gap-1.5 text-xs">
            <Shield class="w-3.5 h-3.5" /> Isolate
          </button>
          <button @click="performAction('unisolate')" :disabled="actionLoading" class="btn-ghost flex items-center gap-1.5 text-xs">
            <ShieldOff class="w-3.5 h-3.5" /> Release
          </button>
          <button @click="performAction('quickScan')" :disabled="actionLoading" class="btn-ghost flex items-center gap-1.5 text-xs">
            <Search class="w-3.5 h-3.5" /> Quick Scan
          </button>
          <button @click="performAction('fullScan')" :disabled="actionLoading" class="btn-ghost flex items-center gap-1.5 text-xs">
            <Search class="w-3.5 h-3.5" /> Full Scan
          </button>
        </div>

        <div class="space-y-2 text-sm">
          <div v-for="[k, v] in [
            ['Machine ID', machine.machineId],
            ['OS Platform', machine.osPlatform],
            ['OS Version', machine.osVersion],
            ['Health Status', machine.healthStatus],
            ['Risk Score', machine.riskScore],
            ['Exposure Level', machine.exposureLevel],
            ['Agent Version', machine.agentVersion],
            ['Last IP', machine.lastIpAddress],
            ['External IP', machine.lastExternalIpAddress],
            ['AAD Joined', machine.isAadJoined ? 'Yes' : 'No'],
            ['RBAC Group', machine.rbacGroupName],
            ['First Seen', machine.firstSeen?.slice(0, 10)],
            ['Last Seen', machine.lastSeen?.slice(0, 10)],
          ]" :key="(k as string)" class="flex justify-between gap-2">
            <span class="text-s1-muted">{{ k }}</span>
            <span class="text-s1-text text-right truncate max-w-[60%] font-mono text-xs">{{ v ?? '--' }}</span>
          </div>

          <!-- Tags -->
          <div v-if="machine.machineTags?.length" class="pt-2">
            <div class="text-s1-muted text-xs mb-1.5">Tags</div>
            <div class="flex flex-wrap gap-1">
              <span v-for="tag in machine.machineTags" :key="tag"
                class="text-xs px-2 py-0.5 rounded-full bg-green-500/20 text-green-400 font-medium">
                {{ tag }}
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
              ? 'text-green-400 border-green-500'
              : 'text-s1-muted border-transparent hover:text-s1-text'"
          >
            {{ tab.label }}
          </button>
        </div>

        <div class="p-5 overflow-y-auto max-h-[70vh]">
          <!-- Overview -->
          <div v-if="activeTab === 'overview'" class="space-y-5">
            <div>
              <div class="text-xs font-semibold text-s1-muted uppercase tracking-wider mb-2">Machine Information</div>
              <div class="grid grid-cols-2 gap-x-6 gap-y-0 text-sm">
                <div v-for="[k, v] in [
                  ['Computer Name', machine.computerDnsName],
                  ['Machine ID', machine.machineId],
                  ['OS Platform', machine.osPlatform],
                  ['OS Version', machine.osVersion],
                  ['Health Status', machine.healthStatus],
                  ['Risk Score', machine.riskScore],
                  ['Exposure Level', machine.exposureLevel],
                  ['Agent Version', machine.agentVersion],
                  ['AAD Device ID', machine.aadDeviceId],
                  ['RBAC Group', machine.rbacGroupName],
                  ['First Seen', machine.firstSeen],
                  ['Last Seen', machine.lastSeen],
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
              No alerts for this machine
            </div>
            <table v-else class="w-full">
              <thead class="border-b border-s1-border">
                <tr>
                  <th class="table-header text-left">Title</th>
                  <th class="table-header text-left">Severity</th>
                  <th class="table-header text-left">Status</th>
                  <th class="table-header text-left">Category</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="alert in alerts" :key="alert.alertId" class="table-row">
                  <td class="table-cell">
                    <div class="font-medium text-s1-text text-sm truncate max-w-[200px]">{{ alert.title }}</div>
                  </td>
                  <td class="table-cell">
                    <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                      :class="severityBadgeClass(alert.severity)">
                      {{ alert.severity }}
                    </span>
                  </td>
                  <td class="table-cell text-sm text-s1-subtle">{{ alert.status }}</td>
                  <td class="table-cell text-sm text-s1-subtle">{{ alert.category }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <div v-else class="card p-10 text-center">
      <p class="text-s1-muted">Machine not found</p>
      <button @click="router.push('/defender/machines')" class="btn-ghost mt-4 text-sm">Back to machines</button>
    </div>
  </div>
</template>
