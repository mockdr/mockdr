<script setup lang="ts">
import { onMounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import { RefreshCw, Wifi, WifiOff, Scan, Trash2 } from 'lucide-vue-next'
import { useAgentsStore } from '../stores/agents'
import { relativeTime } from '../utils/formatters'
import StatusBadge from '../components/shared/StatusBadge.vue'
import OsIcon from '../components/shared/OsIcon.vue'
import LoadingSkeleton from '../components/shared/LoadingSkeleton.vue'
import EmptyState from '../components/shared/EmptyState.vue'

const router = useRouter()
const store = useAgentsStore()

onMounted(() => store.fetchList())

const allSelected = computed(() =>
  store.items.length > 0 && store.items.every((a) => store.isSelected(a))
)

function toggleAll(): void {
  if (allSelected.value) store.clearSelection()
  else store.items.forEach((a) => { if (!store.isSelected(a)) store.toggleSelect(a) })
}


</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text">Endpoints</h1>
        <p class="text-s1-muted text-sm">{{ store.total }} agents total</p>
      </div>
      <button @click="store.fetchList()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="store.loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Filter bar -->
    <div class="card p-4 flex flex-wrap gap-3">
      <input
        v-model="store.filters.query"
        class="input flex-1 min-w-[200px]"
        placeholder="Search hostname, IP, OS..."
      />
      <select v-model="store.filters.osTypes" class="select">
        <option value="">All OS</option>
        <option value="windows">Windows</option>
        <option value="macos">macOS</option>
        <option value="linux">Linux</option>
      </select>
      <select v-model="store.filters.networkStatuses" class="select">
        <option value="">All Status</option>
        <option value="connected">Connected</option>
        <option value="disconnected">Disconnected</option>
      </select>
    </div>

    <!-- Bulk action bar -->
    <Transition name="slide-down">
      <div v-if="store.selected.length > 0" class="card px-4 py-3 flex items-center gap-3 border-s1-primary/40">
        <span class="text-sm text-s1-text font-medium">{{ store.selected.length }} selected</span>
        <div class="h-4 w-px bg-s1-border"></div>
        <button @click="store.performAction('disconnect')" :disabled="store.loading" class="btn-ghost flex items-center gap-1.5 text-xs">
          <WifiOff class="w-3.5 h-3.5" /> Isolate
        </button>
        <button @click="store.performAction('connect')" :disabled="store.loading" class="btn-ghost flex items-center gap-1.5 text-xs">
          <Wifi class="w-3.5 h-3.5" /> Reconnect
        </button>
        <button @click="store.performAction('initiate-scan')" :disabled="store.loading" class="btn-ghost flex items-center gap-1.5 text-xs">
          <Scan class="w-3.5 h-3.5" /> Scan
        </button>
        <button @click="store.performAction('decommission')" :disabled="store.loading" class="btn-danger flex items-center gap-1.5 text-xs ml-auto">
          <Trash2 class="w-3.5 h-3.5" /> Decommission
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
                class="rounded border-s1-border bg-s1-bg accent-s1-primary" />
            </th>
            <th class="table-header text-left">Computer</th>
            <th class="table-header text-left">IP Address</th>
            <th class="table-header text-left">OS</th>
            <th class="table-header text-left">Agent Version</th>
            <th class="table-header text-left">Network</th>
            <th class="table-header text-left">Group</th>
            <th class="table-header text-left">Last Seen</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="store.loading && !store.items.length" :rows="8" />
          <template v-else>
            <tr
              v-for="agent in store.items" :key="agent.id"
              class="table-row"
              :class="store.isSelected(agent) ? 'bg-s1-primary/5' : ''"
              @click="router.push(`/endpoints/${agent.id}`)"
            >
              <td class="table-cell" @click.stop>
                <input type="checkbox" :checked="store.isSelected(agent)"
                  @change="store.toggleSelect(agent)"
                  class="rounded border-s1-border bg-s1-bg accent-s1-primary" />
              </td>
              <td class="table-cell">
                <div class="flex items-center gap-2">
                  <OsIcon :os-type="agent.osType" />
                  <div>
                    <div class="font-medium text-s1-text text-sm">{{ agent.computerName }}</div>
                    <div v-if="agent.infected" class="text-xs text-s1-danger">⚠ Infected</div>
                  </div>
                </div>
              </td>
              <td class="table-cell">
                <div class="text-sm">{{ agent.lastIpToMgmt }}</div>
                <div class="text-xs text-s1-muted">{{ agent.externalIp }}</div>
              </td>
              <td class="table-cell">
                <div class="text-sm text-s1-subtle">{{ agent.osName }}</div>
              </td>
              <td class="table-cell">
                <span class="font-mono text-xs text-s1-muted">{{ agent.agentVersion }}</span>
              </td>
              <td class="table-cell">
                <StatusBadge :status="agent.networkStatus" type="agent" />
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ agent.groupName }}</td>
              <td class="table-cell text-xs text-s1-muted">{{ relativeTime(agent.lastActiveDate) }}</td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!store.loading && !store.items.length"
        icon="💻"
        title="No endpoints found"
        description="No endpoints match your current filters."
      />

      <!-- Load more -->
      <div v-if="store.nextCursor" class="p-4 text-center border-t border-s1-border">
        <button @click="store.fetchList(false)" class="btn-ghost text-sm">
          Load more endpoints
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.slide-down-enter-active, .slide-down-leave-active { transition: all 0.2s; }
.slide-down-enter-from, .slide-down-leave-to { opacity: 0; transform: translateY(-8px); }
</style>
