<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { RefreshCw, Shield, ShieldOff } from 'lucide-vue-next'
import { ensureMdeAuth, mdeMachinesApi } from '../../api/defender'
import type { MdeMachine } from '../../types/defender'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const router = useRouter()
const loading = ref(false)
const machines = ref<MdeMachine[]>([])
const total = ref(0)
const skip = ref(0)
const top = 25

// Filters
const filterPlatform = ref('')
const filterHealth = ref('')
const filterRisk = ref('')

// Selection
const selected = ref<Set<string>>(new Set())

const allSelected = computed(() =>
  machines.value.length > 0 && machines.value.every(m => selected.value.has(m.machineId)),
)

function toggleAll(): void {
  if (allSelected.value) {
    selected.value = new Set()
  } else {
    selected.value = new Set(machines.value.map(m => m.machineId))
  }
}

function toggleSelect(id: string): void {
  const next = new Set(selected.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  selected.value = next
}

function healthBadgeClass(status: string): string {
  switch (status) {
    case 'Active': return 'bg-green-500/15 text-green-400'
    case 'Inactive': return 'bg-yellow-500/15 text-yellow-400'
    case 'ImpairedCommunication': return 'bg-red-500/15 text-red-400'
    case 'NoCommunication': return 'bg-gray-500/15 text-gray-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function riskBadgeClass(risk: string): string {
  switch (risk) {
    case 'High': return 'bg-red-500/15 text-red-400'
    case 'Medium': return 'bg-orange-500/15 text-orange-400'
    case 'Low': return 'bg-green-500/15 text-green-400'
    case 'None': return 'bg-gray-500/15 text-gray-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function fetchMachines(direction: 'next' | 'prev' | 'reset' = 'reset'): Promise<void> {
  loading.value = true
  try {
    await ensureMdeAuth()

    if (direction === 'next') {
      skip.value += top
    } else if (direction === 'prev') {
      skip.value = Math.max(0, skip.value - top)
    } else {
      skip.value = 0
    }

    const params: Record<string, unknown> = {
      $top: top,
      $skip: skip.value,
    }

    // Build OData $filter
    const filters: string[] = []
    if (filterPlatform.value) filters.push(`osPlatform eq '${filterPlatform.value}'`)
    if (filterHealth.value) filters.push(`healthStatus eq '${filterHealth.value}'`)
    if (filterRisk.value) filters.push(`riskScore eq '${filterRisk.value}'`)
    if (filters.length) params['$filter'] = filters.join(' and ')

    const res = await mdeMachinesApi.list(params)
    machines.value = res.value ?? []
    // OData doesn't always give total, estimate from results
    if (machines.value.length === top) {
      total.value = Math.max(total.value, skip.value + top + 1)
    } else {
      total.value = skip.value + machines.value.length
    }
  } finally {
    loading.value = false
  }
}

const hasPrev = computed(() => skip.value > 0)
const hasNext = computed(() => machines.value.length === top)

async function performAction(action: 'isolate' | 'unisolate'): Promise<void> {
  if (selected.value.size === 0) return
  loading.value = true
  try {
    const ids = [...selected.value]
    for (const id of ids) {
      if (action === 'isolate') {
        await mdeMachinesApi.isolate(id, 'Isolated from UI')
      } else {
        await mdeMachinesApi.unisolate(id, 'Released from UI')
      }
    }
    selected.value = new Set()
    await fetchMachines()
  } finally {
    loading.value = false
  }
}

watch([filterPlatform, filterHealth, filterRisk], () => fetchMachines())

onMounted(() => fetchMachines())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="text-green-500 font-bold">MDE</span> Machines
        </h1>
        <p class="text-s1-muted text-sm">Defender for Endpoint devices</p>
      </div>
      <button @click="fetchMachines()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Filter bar -->
    <div class="card p-4 flex flex-wrap gap-3">
      <select v-model="filterPlatform" class="select">
        <option value="">All Platforms</option>
        <option value="Windows10">Windows 10</option>
        <option value="Windows11">Windows 11</option>
        <option value="WindowsServer2019">Windows Server 2019</option>
        <option value="Linux">Linux</option>
        <option value="macOS">macOS</option>
      </select>
      <select v-model="filterHealth" class="select">
        <option value="">All Health</option>
        <option value="Active">Active</option>
        <option value="Inactive">Inactive</option>
        <option value="ImpairedCommunication">Impaired</option>
        <option value="NoCommunication">No Communication</option>
      </select>
      <select v-model="filterRisk" class="select">
        <option value="">All Risk</option>
        <option value="High">High</option>
        <option value="Medium">Medium</option>
        <option value="Low">Low</option>
        <option value="None">None</option>
      </select>
    </div>

    <!-- Bulk action bar -->
    <Transition name="slide-down">
      <div v-if="selected.size > 0" class="card px-4 py-3 flex items-center gap-3 border-green-500/40">
        <span class="text-sm text-s1-text font-medium">{{ selected.size }} selected</span>
        <div class="h-4 w-px bg-s1-border"></div>
        <button @click="performAction('isolate')" class="btn-ghost flex items-center gap-1.5 text-xs">
          <Shield class="w-3.5 h-3.5" /> Isolate
        </button>
        <button @click="performAction('unisolate')" class="btn-ghost flex items-center gap-1.5 text-xs">
          <ShieldOff class="w-3.5 h-3.5" /> Release
        </button>
      </div>
    </Transition>

    <!-- Table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header w-10">
              <input type="checkbox" :checked="allSelected" @change="toggleAll"
                class="rounded border-s1-border bg-s1-bg accent-green-500" />
            </th>
            <th class="table-header text-left">Computer Name</th>
            <th class="table-header text-left">OS Platform</th>
            <th class="table-header text-left">Health Status</th>
            <th class="table-header text-left">Risk Score</th>
            <th class="table-header text-left">Last Seen</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !machines.length" :rows="8" />
          <template v-else>
            <tr
              v-for="machine in machines" :key="machine.machineId"
              class="table-row"
              :class="selected.has(machine.machineId) ? 'bg-green-500/5' : ''"
              @click="router.push(`/defender/machines/${machine.machineId}`)"
            >
              <td class="table-cell" @click.stop>
                <input type="checkbox" :checked="selected.has(machine.machineId)"
                  @change="toggleSelect(machine.machineId)"
                  class="rounded border-s1-border bg-s1-bg accent-green-500" />
              </td>
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ machine.computerDnsName }}</div>
                <div class="text-xs text-s1-muted">{{ machine.lastIpAddress }}</div>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ machine.osPlatform }}</td>
              <td class="table-cell">
                <span
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="healthBadgeClass(machine.healthStatus)"
                >
                  {{ machine.healthStatus }}
                </span>
              </td>
              <td class="table-cell">
                <span
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="riskBadgeClass(machine.riskScore)"
                >
                  {{ machine.riskScore }}
                </span>
              </td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(machine.lastSeen) }}</td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !machines.length"
        icon="--"
        title="No machines found"
        description="No machines match your current filters."
      />

      <!-- Pagination -->
      <div v-if="machines.length > 0" class="p-4 flex items-center justify-between border-t border-s1-border">
        <button @click="fetchMachines('prev')" class="btn-ghost text-sm" :disabled="!hasPrev || loading">
          Previous
        </button>
        <span class="text-xs text-s1-muted">
          Showing {{ skip + 1 }}–{{ skip + machines.length }}
        </span>
        <button @click="fetchMachines('next')" class="btn-ghost text-sm" :disabled="!hasNext || loading">
          Next
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.slide-down-enter-active, .slide-down-leave-active { transition: all 0.2s; }
.slide-down-enter-from, .slide-down-leave-to { opacity: 0; transform: translateY(-8px); }
</style>
