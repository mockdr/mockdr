<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { RefreshCw } from 'lucide-vue-next'
import { ensureGraphAuth, graphGroupsApi } from '../../api/graph'
import type { GraphGroup, GraphUser } from '../../types/graph'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

const route = useRoute()
const loading = ref(false)
const group = ref<GraphGroup | null>(null)
const members = ref<GraphUser[]>([])

function groupType(g: GraphGroup): string {
  if (g.groupTypes.includes('Unified')) return 'Microsoft 365'
  if (g.groupTypes.includes('DynamicMembership')) return 'Dynamic'
  if (g.securityEnabled) return 'Security'
  return 'Distribution'
}

function groupTypeBadgeClass(type: string): string {
  switch (type) {
    case 'Microsoft 365': return 'bg-blue-500/15 text-blue-400'
    case 'Security': return 'bg-green-500/15 text-green-400'
    case 'Dynamic': return 'bg-yellow-500/15 text-yellow-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

async function fetchGroup(): Promise<void> {
  loading.value = true
  try {
    await ensureGraphAuth()
    const id = route.params.id as string
    group.value = await graphGroupsApi.get(id)
    const res = await graphGroupsApi.getMembers(id)
    members.value = res.value ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchGroup())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="font-bold" style="color: #0078D4">Graph</span> Group Detail
        </h1>
        <p class="text-s1-muted text-sm">{{ group?.displayName ?? 'Loading...' }}</p>
      </div>
      <button @click="fetchGroup()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <LoadingSkeleton v-if="loading && !group" :rows="6" />

    <template v-if="group">
      <!-- Group Info Card -->
      <div class="card p-5 space-y-3">
        <h2 class="text-sm font-semibold text-s1-text">Group Information</h2>
        <div class="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span class="text-s1-muted">Display Name</span>
            <div class="text-s1-text font-medium">{{ group.displayName }}</div>
          </div>
          <div>
            <span class="text-s1-muted">Type</span>
            <div>
              <span
                class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                :class="groupTypeBadgeClass(groupType(group))"
              >
                {{ groupType(group) }}
              </span>
            </div>
          </div>
          <div>
            <span class="text-s1-muted">Description</span>
            <div class="text-s1-text">{{ group.description || '—' }}</div>
          </div>
          <div>
            <span class="text-s1-muted">Security Enabled</span>
            <div class="text-s1-text">{{ group.securityEnabled ? 'Yes' : 'No' }}</div>
          </div>
          <div v-if="group.membershipRule">
            <span class="text-s1-muted">Membership Rule</span>
            <div class="text-s1-text font-mono text-xs">{{ group.membershipRule }}</div>
          </div>
        </div>
      </div>

      <!-- Members Table -->
      <div class="card overflow-hidden">
        <div class="px-4 py-3 border-b border-s1-border">
          <h2 class="text-sm font-semibold text-s1-text">Members ({{ members.length }})</h2>
        </div>
        <table class="w-full">
          <thead class="border-b border-s1-border">
            <tr>
              <th class="table-header text-left">Display Name</th>
              <th class="table-header text-left">UPN</th>
              <th class="table-header text-left">Department</th>
              <th class="table-header text-left">Job Title</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="member in members" :key="member.id" class="table-row">
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ member.displayName }}</div>
              </td>
              <td class="table-cell">
                <span class="font-mono text-xs text-s1-muted">{{ member.userPrincipalName }}</span>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ member.department ?? '—' }}</td>
              <td class="table-cell text-sm text-s1-subtle">{{ member.jobTitle ?? '—' }}</td>
            </tr>
            <tr v-if="!members.length">
              <td colspan="4" class="table-cell text-sm text-s1-muted text-center py-4">No members found</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </div>
</template>
