<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ensureGraphAuth, graphUsersApi } from '../../api/graph'
import type { GraphUser } from '../../types/graph'
import { relativeTime } from '../../utils/formatters'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const users = ref<GraphUser[]>([])

function statusBadgeClass(enabled: boolean): string {
  return enabled
    ? 'bg-green-500/15 text-green-400'
    : 'bg-red-500/15 text-red-400'
}

async function fetchUsers(): Promise<void> {
  loading.value = true
  try {
    await ensureGraphAuth()
    const res = await graphUsersApi.list({
      $select: 'id,displayName,userPrincipalName,department,jobTitle,accountEnabled,signInActivity',
      $top: 999,
    })
    users.value = res.value ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchUsers())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="font-bold" style="color: #0078D4">Graph</span> Users
        </h1>
        <p class="text-s1-muted text-sm">Entra ID user accounts</p>
      </div>
      <button @click="fetchUsers()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Table -->
    <div class="card overflow-hidden">
      <table class="w-full">
        <thead class="border-b border-s1-border">
          <tr>
            <th class="table-header text-left">Display Name</th>
            <th class="table-header text-left">UPN</th>
            <th class="table-header text-left">Department</th>
            <th class="table-header text-left">Job Title</th>
            <th class="table-header text-left">Account Status</th>
            <th class="table-header text-left">Last Sign-In</th>
          </tr>
        </thead>
        <tbody>
          <LoadingSkeleton v-if="loading && !users.length" :rows="8" />
          <template v-else>
            <tr v-for="user in users" :key="user.id" class="table-row">
              <td class="table-cell">
                <div class="font-medium text-s1-text text-sm">{{ user.displayName }}</div>
              </td>
              <td class="table-cell">
                <span class="font-mono text-xs text-s1-muted">{{ user.userPrincipalName }}</span>
              </td>
              <td class="table-cell text-sm text-s1-subtle">{{ user.department ?? '—' }}</td>
              <td class="table-cell text-sm text-s1-subtle">{{ user.jobTitle ?? '—' }}</td>
              <td class="table-cell">
                <span
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
                  :class="statusBadgeClass(user.accountEnabled)"
                >
                  {{ user.accountEnabled ? 'Enabled' : 'Disabled' }}
                </span>
              </td>
              <td class="table-cell text-xs text-s1-muted">
                {{ user.signInActivity?.lastSignInDateTime
                  ? relativeTime(user.signInActivity.lastSignInDateTime)
                  : '—' }}
              </td>
            </tr>
          </template>
        </tbody>
      </table>

      <EmptyState
        v-if="!loading && !users.length"
        icon="--"
        title="No users found"
        description="No Entra ID users available."
      />
    </div>
  </div>
</template>
