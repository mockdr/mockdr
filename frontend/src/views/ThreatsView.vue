<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { RefreshCw, ShieldCheck, ShieldOff, CheckCircle, Lock } from 'lucide-vue-next'
import { useThreatsStore } from '../stores/threats'
import StatusBadge from '../components/shared/StatusBadge.vue'
import LoadingSkeleton from '../components/shared/LoadingSkeleton.vue'
import EmptyState from '../components/shared/EmptyState.vue'

const router = useRouter()
const store = useThreatsStore()

onMounted(() => store.fetchList())

const selected = ref<Set<string>>(new Set())

const allSelected = computed(() =>
  store.items.length > 0 && store.items.every((t) => selected.value.has(t.id))
)

function toggleAll(): void {
  if (allSelected.value) {
    selected.value = new Set()
  } else {
    selected.value = new Set(store.items.map((t) => t.id))
  }
}

function toggleSelect(id: string): void {
  const next = new Set(selected.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  selected.value = next
}

function formatDate(ts: string): string {
  return ts ? new Date(ts).toLocaleDateString() : '—'
}
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text">Threats</h1>
        <p class="text-s1-muted text-sm">{{ store.total }} threats total</p>
      </div>
      <button @click="store.fetchList()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="store.loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Filters -->
    <div class="card p-4 flex flex-wrap gap-3">
      <input v-model="store.filters.query" class="input flex-1 min-w-[200px]" placeholder="Search threats..." />
      <select v-model="store.filters.classifications" class="select">
        <option value="">All Classifications</option>
        <option value="Malware">Malware</option>
        <option value="Ransomware">Ransomware</option>
        <option value="PUA">PUA</option>
        <option value="Exploit">Exploit</option>
        <option value="Trojan">Trojan</option>
      </select>
      <select v-model="store.filters.mitigationStatuses" class="select">
        <option value="">All Statuses</option>
        <option value="active">Active</option>
        <option value="mitigated">Mitigated</option>
        <option value="blocked">Blocked</option>
        <option value="suspicious">Suspicious</option>
      </select>
      <select v-model="store.filters.incidentStatuses" class="select">
        <option value="">All Incidents</option>
        <option value="unresolved">Unresolved</option>
        <option value="in_progress">In Progress</option>
        <option value="resolved">Resolved</option>
      </select>
    </div>

    <!-- Bulk action toolbar -->
    <Transition name="slide-down">
      <div v-if="selected.size > 0" class="card px-4 py-3 flex items-center gap-3 border-s1-primary/40">
        <span class="text-sm text-s1-text font-medium">{{ selected.size }} selected</span>
        <div class="h-4 w-px bg-s1-border"></div>
        <button @click="store.performAction('mark-as-threat', [...selected])" :disabled="store.loading" class="btn-ghost flex items-center gap-1.5 text-xs">
          <ShieldOff class="w-3.5 h-3.5 text-s1-danger" /> Mark as Threat
        </button>
        <button @click="store.performAction('mark-as-benign', [...selected])" :disabled="store.loading" class="btn-ghost flex items-center gap-1.5 text-xs">
          <ShieldCheck class="w-3.5 h-3.5 text-s1-success" /> Mark as Benign
        </button>
        <button @click="store.performAction('resolve', [...selected])" :disabled="store.loading" class="btn-ghost flex items-center gap-1.5 text-xs">
          <CheckCircle class="w-3.5 h-3.5 text-s1-success" /> Resolve
        </button>
        <button @click="store.performAction('add-to-blocklist', [...selected])" :disabled="store.loading" class="btn-ghost flex items-center gap-1.5 text-xs">
          <Lock class="w-3.5 h-3.5 text-s1-warning" /> Add to Blocklist
        </button>
      </div>
    </Transition>

    <!-- Table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header w-10">
              <input type="checkbox" :checked="allSelected" @change="toggleAll" class="rounded border-s1-border bg-s1-bg accent-s1-primary" />
            </th>
            <th class="table-header text-left">Threat Name</th>
            <th class="table-header text-left">Classification</th>
            <th class="table-header text-left">Endpoint</th>
            <th class="table-header text-left">Mitigation</th>
            <th class="table-header text-left">Incident</th>
            <th class="table-header text-left">Verdict</th>
            <th class="table-header text-left">Detected</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="store.loading && !store.items.length" :rows="8" />
          <template v-else>
            <tr
              v-for="threat in store.items" :key="threat.id"
              class="table-row"
              @click="router.push(`/threats/${threat.id}`)"
            >
              <td class="table-cell" @click.stop>
                <input type="checkbox"
                  :checked="selected.has(threat.id)"
                  @change="toggleSelect(threat.id)"
                  class="rounded border-s1-border bg-s1-bg accent-s1-primary" />
              </td>
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ threat.threatInfo.threatName }}</div>
                <div class="text-xs text-s1-muted font-mono">{{ threat.threatInfo.sha1?.slice(0, 12) }}...</div>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ threat.threatInfo.classification }}</td>
              <td class="table-cell text-sm text-s1-subtle">{{ threat.agentDetectionInfo.agentComputerName }}</td>
              <td class="table-cell"><StatusBadge :status="threat.threatInfo.mitigationStatus" type="threat" /></td>
              <td class="table-cell"><StatusBadge :status="threat.threatInfo.incidentStatus" type="incident" /></td>
              <td class="table-cell"><StatusBadge :status="threat.threatInfo.analystVerdict" type="verdict" /></td>
              <td class="table-cell text-xs text-s1-muted">{{ formatDate(threat.threatInfo.createdAt) }}</td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState v-if="!store.loading && !store.items.length" icon="🛡️" title="No threats found" description="No threats match your current filters." />

      <div v-if="store.nextCursor" class="p-4 text-center border-t border-s1-border">
        <button @click="store.fetchList(false)" class="btn-ghost text-sm">Load more threats</button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.slide-down-enter-active, .slide-down-leave-active { transition: all 0.2s; }
.slide-down-enter-from, .slide-down-leave-to { opacity: 0; transform: translateY(-8px); }
</style>
