<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { RefreshCw, Shield, ShieldOff } from 'lucide-vue-next'
import { ensureCsAuth, csHostsApi } from '../../api/crowdstrike'
import { relativeTime } from '../../utils/formatters'
import type { CsHost } from '../../types/crowdstrike'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const router = useRouter()
const loading = ref(false)
const hosts = ref<CsHost[]>([])
const total = ref(0)
const offset = ref(0)
const limit = 25

// Filters
const filterPlatform = ref('')
const filterStatus = ref('')

// Selection
const selected = ref<Set<string>>(new Set())

const allSelected = computed(() =>
  hosts.value.length > 0 && hosts.value.every(h => selected.value.has(h.device_id)),
)

function toggleAll(): void {
  if (allSelected.value) {
    selected.value = new Set()
  } else {
    selected.value = new Set(hosts.value.map(h => h.device_id))
  }
}

function toggleSelect(id: string): void {
  const next = new Set(selected.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  selected.value = next
}

function platformIcon(platform: string): string {
  switch (platform) {
    case 'Windows': return 'W'
    case 'Mac': return 'M'
    case 'Linux': return 'L'
    default: return '?'
  }
}

function platformColor(platform: string): string {
  switch (platform) {
    case 'Windows': return 'bg-red-500/20 text-red-400'
    case 'Mac': return 'bg-orange-500/20 text-orange-400'
    case 'Linux': return 'bg-yellow-500/20 text-yellow-400'
    default: return 'bg-gray-500/20 text-gray-400'
  }
}

async function fetchHosts(append = false): Promise<void> {
  loading.value = true
  try {
    await ensureCsAuth()

    const params: Record<string, unknown> = {
      offset: append ? offset.value : 0,
      limit,
    }

    // Build FQL filter
    const filters: string[] = []
    if (filterPlatform.value) filters.push(`platform_name:'${filterPlatform.value}'`)
    if (filterStatus.value) filters.push(`status:'${filterStatus.value}'`)
    if (filters.length) params['filter'] = filters.join('+')

    const idsRes = await csHostsApi.queryIds(params)
    total.value = idsRes.meta.pagination?.total ?? idsRes.resources.length

    if (idsRes.resources.length === 0) {
      if (!append) hosts.value = []
      return
    }

    const entitiesRes = await csHostsApi.getEntities(idsRes.resources)

    if (append) {
      hosts.value = [...hosts.value, ...entitiesRes.resources]
    } else {
      hosts.value = entitiesRes.resources
      offset.value = 0
    }
    offset.value += idsRes.resources.length
  } finally {
    loading.value = false
  }
}

const hasMore = computed(() => offset.value < total.value)

async function performAction(action: string): Promise<void> {
  if (selected.value.size === 0) return
  loading.value = true
  try {
    await csHostsApi.action(action, [...selected.value])
    selected.value = new Set()
    await fetchHosts()
  } finally {
    loading.value = false
  }
}

// Re-fetch when filters change
watch([filterPlatform, filterStatus], () => fetchHosts())

onMounted(() => fetchHosts())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="text-red-500 font-bold">CS</span> Hosts
        </h1>
        <p class="text-s1-muted text-sm">{{ total }} devices total</p>
      </div>
      <button @click="fetchHosts()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Filter bar -->
    <div class="card p-4 flex flex-wrap gap-3">
      <select v-model="filterPlatform" class="select">
        <option value="">All Platforms</option>
        <option value="Windows">Windows</option>
        <option value="Mac">Mac</option>
        <option value="Linux">Linux</option>
      </select>
      <select v-model="filterStatus" class="select">
        <option value="">All Status</option>
        <option value="normal">Normal</option>
        <option value="contained">Contained</option>
        <option value="containment_pending">Containment Pending</option>
        <option value="lift_containment_pending">Lift Containment Pending</option>
      </select>
    </div>

    <!-- Bulk action bar -->
    <Transition name="slide-down">
      <div v-if="selected.size > 0" class="card px-4 py-3 flex items-center gap-3 border-red-500/40">
        <span class="text-sm text-s1-text font-medium">{{ selected.size }} selected</span>
        <div class="h-4 w-px bg-s1-border"></div>
        <button @click="performAction('contain')" class="btn-ghost flex items-center gap-1.5 text-xs">
          <Shield class="w-3.5 h-3.5" /> Contain
        </button>
        <button @click="performAction('lift_containment')" class="btn-ghost flex items-center gap-1.5 text-xs">
          <ShieldOff class="w-3.5 h-3.5" /> Lift Containment
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
                class="rounded border-s1-border bg-s1-bg accent-red-500" />
            </th>
            <th class="table-header text-left">Hostname</th>
            <th class="table-header text-left">Platform</th>
            <th class="table-header text-left">OS Version</th>
            <th class="table-header text-left">External IP</th>
            <th class="table-header text-left">Status</th>
            <th class="table-header text-left">Agent Version</th>
            <th class="table-header text-left">Last Seen</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !hosts.length" :rows="8" />
          <template v-else>
            <tr
              v-for="host in hosts" :key="host.device_id"
              class="table-row"
              :class="selected.has(host.device_id) ? 'bg-red-500/5' : ''"
              @click="router.push(`/crowdstrike/hosts/${host.device_id}`)"
            >
              <td class="table-cell" @click.stop>
                <input type="checkbox" :checked="selected.has(host.device_id)"
                  @change="toggleSelect(host.device_id)"
                  class="rounded border-s1-border bg-s1-bg accent-red-500" />
              </td>
              <td class="table-cell">
                <div class="flex items-center gap-2">
                  <span
                    class="w-6 h-6 rounded flex items-center justify-center text-xs font-bold"
                    :class="platformColor(host.platform_name)"
                  >{{ platformIcon(host.platform_name) }}</span>
                  <div>
                    <div class="font-medium text-s1-text text-sm">{{ host.hostname }}</div>
                    <div class="text-xs text-s1-muted">{{ host.product_type_desc }}</div>
                  </div>
                </div>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ host.platform_name }}</td>
              <td class="table-cell text-sm text-s1-subtle">{{ host.os_version }}</td>
              <td class="table-cell">
                <span class="font-mono text-xs text-s1-muted">{{ host.external_ip }}</span>
              </td>
              <td class="table-cell">
                <span
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="{
                    'bg-green-500/15 text-green-400': host.status === 'normal',
                    'bg-red-500/15 text-red-400': host.status === 'contained',
                    'bg-yellow-500/15 text-yellow-400': host.status === 'containment_pending' || host.status === 'lift_containment_pending',
                    'bg-gray-500/15 text-gray-400': !['normal', 'contained', 'containment_pending', 'lift_containment_pending'].includes(host.status),
                  }"
                >
                  {{ host.status }}
                </span>
              </td>
              <td class="table-cell">
                <span class="font-mono text-xs text-s1-muted">{{ host.agent_version }}</span>
              </td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(host.last_seen) }}</td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !hosts.length"
        icon="--"
        title="No hosts found"
        description="No hosts match your current filters."
      />

      <!-- Load more -->
      <div v-if="hasMore" class="p-4 text-center border-t border-s1-border">
        <button @click="fetchHosts(true)" class="btn-ghost text-sm" :disabled="loading">
          Load more hosts
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.slide-down-enter-active, .slide-down-leave-active { transition: all 0.2s; }
.slide-down-enter-from, .slide-down-leave-to { opacity: 0; transform: translateY(-8px); }
</style>
