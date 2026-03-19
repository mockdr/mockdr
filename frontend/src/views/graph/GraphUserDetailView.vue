<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { RefreshCw } from 'lucide-vue-next'
import { ensureGraphAuth, graphUsersApi, graphClient } from '../../api/graph'
import type { GraphUser, GraphGroup } from '../../types/graph'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'

const route = useRoute()
const loading = ref(false)
const user = ref<GraphUser | null>(null)
const groups = ref<GraphGroup[]>([])

function statusBadgeClass(enabled: boolean): string {
  return enabled
    ? 'bg-green-500/15 text-green-400'
    : 'bg-red-500/15 text-red-400'
}

async function fetchUser(): Promise<void> {
  loading.value = true
  try {
    await ensureGraphAuth()
    const id = route.params.id as string
    user.value = await graphUsersApi.get(id)
    const memberOfRes = await graphClient.get(`/v1.0/users/${id}/memberOf`) as { value: GraphGroup[] }
    groups.value = memberOfRes.value ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchUser())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="font-bold" style="color: #0078D4">Graph</span> User Detail
        </h1>
        <p class="text-s1-muted text-sm">{{ user?.displayName ?? 'Loading...' }}</p>
      </div>
      <button @click="fetchUser()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <LoadingSkeleton v-if="loading && !user" :rows="6" />

    <template v-if="user">
      <!-- User Info Card -->
      <div class="card p-5 space-y-3">
        <h2 class="text-sm font-semibold text-s1-text">User Information</h2>
        <div class="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span class="text-s1-muted">Display Name</span>
            <div class="text-s1-text font-medium">{{ user.displayName }}</div>
          </div>
          <div>
            <span class="text-s1-muted">UPN</span>
            <div class="text-s1-text font-mono text-xs">{{ user.userPrincipalName }}</div>
          </div>
          <div>
            <span class="text-s1-muted">Mail</span>
            <div class="text-s1-text">{{ user.mail ?? '—' }}</div>
          </div>
          <div>
            <span class="text-s1-muted">Department</span>
            <div class="text-s1-text">{{ user.department ?? '—' }}</div>
          </div>
          <div>
            <span class="text-s1-muted">Job Title</span>
            <div class="text-s1-text">{{ user.jobTitle ?? '—' }}</div>
          </div>
          <div>
            <span class="text-s1-muted">Account Status</span>
            <div>
              <span
                class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                :class="statusBadgeClass(user.accountEnabled)"
              >
                {{ user.accountEnabled ? 'Enabled' : 'Disabled' }}
              </span>
            </div>
          </div>
          <div>
            <span class="text-s1-muted">Last Sign-In</span>
            <div class="text-s1-text text-xs">
              {{ user.signInActivity?.lastSignInDateTime
                ? relativeTime(user.signInActivity.lastSignInDateTime)
                : '—' }}
            </div>
          </div>
        </div>
      </div>

      <!-- Group Memberships -->
      <div class="card overflow-hidden">
        <div class="px-4 py-3 border-b border-s1-border">
          <h2 class="text-sm font-semibold text-s1-text">Group Memberships</h2>
        </div>
        <table class="w-full">
          <thead class="border-b border-s1-border">
            <tr>
              <th class="table-header text-left">Group Name</th>
              <th class="table-header text-left">Description</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="group in groups" :key="group.id" class="table-row">
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ group.displayName }}</div>
              </td>
              <td class="table-cell text-sm text-s1-muted truncate max-w-[300px]">
                {{ group.description || '—' }}
              </td>
            </tr>
            <tr v-if="!groups.length">
              <td colspan="2" class="table-cell text-sm text-s1-muted text-center py-4">No group memberships found</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </div>
</template>
