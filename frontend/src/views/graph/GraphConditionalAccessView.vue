<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ensureGraphAuth, graphIdentityApi } from '../../api/graph'
import type { GraphConditionalAccessPolicy } from '../../types/graph'
import LoadingSkeleton from '../../components/shared/LoadingSkeleton.vue'
import EmptyState from '../../components/shared/EmptyState.vue'

const loading = ref(false)
const policies = ref<GraphConditionalAccessPolicy[]>([])

function stateBadgeClass(state: string): string {
  switch (state) {
    case 'enabled': return 'bg-green-500/15 text-green-400'
    case 'disabled': return 'bg-gray-500/15 text-gray-400'
    case 'enabledForReportingButNotEnforced': return 'bg-yellow-500/15 text-yellow-400'
    default: return 'bg-gray-500/15 text-gray-400'
  }
}

function stateLabel(state: string): string {
  switch (state) {
    case 'enabled': return 'Enabled'
    case 'disabled': return 'Disabled'
    case 'enabledForReportingButNotEnforced': return 'Report Only'
    default: return state
  }
}

function summarizeConditions(conditions: Record<string, unknown> | undefined): string {
  if (!conditions) return '—'
  const parts: string[] = []
  const users = conditions.users as Record<string, unknown> | undefined
  if (users) {
    const includeUsers = users.includeUsers as string[] | undefined
    if (includeUsers?.includes('All')) parts.push('All users')
    else if (Array.isArray(includeUsers)) parts.push(`${includeUsers.length} user(s)`)
  }
  const apps = conditions.applications as Record<string, unknown> | undefined
  if (apps) {
    const includeApps = apps.includeApplications as string[] | undefined
    if (includeApps?.includes('All')) parts.push('All apps')
    else if (Array.isArray(includeApps)) parts.push(`${includeApps.length} app(s)`)
  }
  const platforms = conditions.platforms as Record<string, unknown> | undefined
  if (platforms) {
    const includePlatforms = platforms.includePlatforms as string[] | undefined
    if (Array.isArray(includePlatforms) && includePlatforms.length > 0) {
      parts.push(includePlatforms.join(', '))
    }
  }
  return parts.length > 0 ? parts.join(' | ') : '—'
}

function summarizeGrantControls(grant: Record<string, unknown> | undefined): string {
  if (!grant) return '—'
  const controls = grant.builtInControls as string[] | undefined
  if (Array.isArray(controls) && controls.length > 0) {
    return controls.map(c => {
      switch (c) {
        case 'mfa': return 'Require MFA'
        case 'compliantDevice': return 'Compliant device'
        case 'domainJoinedDevice': return 'Domain joined'
        case 'block': return 'Block access'
        default: return c
      }
    }).join(', ')
  }
  return '—'
}

async function fetchPolicies(): Promise<void> {
  loading.value = true
  try {
    await ensureGraphAuth()
    const res = await graphIdentityApi.listCaPolicies({ $top: 999 })
    policies.value = res.value ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => fetchPolicies())
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-semibold text-s1-text flex items-center gap-2">
          <span class="font-bold" style="color: #0078D4">Graph</span> Conditional Access
        </h1>
        <p class="text-s1-muted text-sm">Entra ID Conditional Access policies</p>
      </div>
      <button @click="fetchPolicies()" class="btn-ghost flex items-center gap-2">
        <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
        Refresh
      </button>
    </div>

    <!-- Loading -->
    <div v-if="loading && !policies.length" class="card p-5">
      <LoadingSkeleton :rows="4" />
    </div>

    <!-- Empty -->
    <EmptyState
      v-if="!loading && !policies.length"
      icon="--"
      title="No CA policies found"
      description="No Conditional Access policies available."
    />

    <!-- Card grid -->
    <div v-if="policies.length" class="grid grid-cols-2 gap-4">
      <div
        v-for="policy in policies" :key="policy.id"
        class="card p-5"
      >
        <div class="flex items-start justify-between mb-3">
          <h3 class="text-sm font-semibold text-s1-text truncate max-w-[70%]">{{ policy.displayName }}</h3>
          <span
            class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
            :class="stateBadgeClass(policy.state)"
          >
            {{ stateLabel(policy.state) }}
          </span>
        </div>
        <div class="space-y-2 text-xs">
          <div>
            <span class="text-s1-muted">Conditions:</span>
            <span class="text-s1-subtle ml-1">{{ summarizeConditions(policy.conditions) }}</span>
          </div>
          <div>
            <span class="text-s1-muted">Grant Controls:</span>
            <span class="text-s1-subtle ml-1">{{ summarizeGrantControls(policy.grantControls) }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
